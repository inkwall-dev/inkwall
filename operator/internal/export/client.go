// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// What a request's answer means (design 0010 §4.3).
type verdict int

const (
	// sent: the sink took the request; rejected counts the events it
	// refused (OTLP's partial success).
	sent verdict = iota
	// retry with backoff, or after the server's Retry-After or RetryInfo.
	retry
	// retrySlow: an authentication failure, retried at the slowest pace,
	// so fixing the Secret resumes the flow without losing what waited.
	retrySlow
	// split the request in half and send both; a single event is dropped
	// as too large.
	split
	// drop: the sink refused the request, and would again.
	drop
)

// Failure kinds, the kind label of the failures metric.
const (
	kindNetwork   = "network"
	kindTLS       = "tls"
	kindTimeout   = "timeout"
	kindAuth      = "auth"
	kindThrottled = "throttled"
	kindServer    = "server"
	kindClient    = "client"
)

// result is a request's answer.
type result struct {
	verdict verdict
	// kind classes a failure; "" on success.
	kind string
	// detail is the HTTP status, the gRPC code or the error's class, with
	// at most maxDetail bytes of the response, escaped: for status and
	// logs, enough to fix a token, not enough to read a service.
	detail string
	// refused is the address class the dialer refused.
	refused string
	// after is the wait the server asked for (Retry-After, RetryInfo).
	after    time.Duration
	rejected int
	// mismatch: the payload doesn't fit the client (a programming error).
	mismatch bool
}

// payloadMismatch is called on a payload a client can't send; tests make
// it fail loudly.
var payloadMismatch = func(string) {}

func mismatched(what string) result {
	payloadMismatch(what)
	return result{verdict: retry, kind: kindClient, detail: "internal: " + what, mismatch: true}
}

const (
	// maxResponse bounds what is read of a response.
	maxResponse = 4 << 10
	// maxDetail bounds what of it goes into status and logs.
	maxDetail = 128
	// maxRetryAfter caps the wait a server asks for.
	maxRetryAfter = 5 * time.Minute
	// splitOver: gRPC RESOURCE_EXHAUSTED without RetryInfo is a message
	// over the server's limit when the request is over this, a quota
	// otherwise.
	splitOver = 1 << 20
)

// payload is a request, encoded for its sink.
type payload struct {
	// body for HTTP, uncompressed; otlp for gRPC.
	body        []byte
	contentType string
	otlp        *collogspb.ExportLogsServiceRequest
	size        int
}

// client sends a sink's requests.
type sinkClient interface {
	send(ctx context.Context, p payload, headers map[string]string) result
	close()
}

// transportConfig is what a sink's connections are made with; a change
// makes a new client (and closes the old one's connections).
type transportConfig struct {
	grpc     bool
	// otlp: an HTTP sink of OTLP (protobuf), not JSON.
	otlp     bool
	url      string // HTTP: the URL; gRPC: host:port
	insecure bool
	gzip     bool
	tls      *tls.Config
}

func newClient(tc transportConfig) (sinkClient, error) {
	if tc.grpc {
		return newGRPCClient(tc)
	}
	return newHTTPClient(tc), nil
}

// httpClient POSTs to a URL: no proxy, no redirects, the guarded dialer.
type httpClient struct {
	url       string
	gzip      bool
	otlp      bool
	transport *http.Transport
	client    *http.Client
}

func newHTTPClient(tc transportConfig) *httpClient {
	t := &http.Transport{
		// The environment's HTTPS_PROXY would put the proxy's address
		// before the dialer's guard instead of the sink's.
		Proxy:                 nil,
		DialContext:           dialContext,
		TLSClientConfig:       tc.tls,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 0,
	}
	return &httpClient{
		url: tc.url, gzip: tc.gzip, otlp: tc.otlp, transport: t,
		client: &http.Client{
			Transport: t,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

var gzipWriters = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}

func compress(body []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(body) / 4)
	zw, _ := gzipWriters.Get().(*gzip.Writer)
	zw.Reset(&buf)
	_, _ = zw.Write(body)
	_ = zw.Close()
	gzipWriters.Put(zw)
	return buf.Bytes()
}

func (c *httpClient) send(ctx context.Context, p payload, headers map[string]string) result {
	if p.body == nil {
		return mismatched("an HTTP sink got a request without a body")
	}
	if (p.otlp != nil) != c.otlp {
		return mismatched("an HTTP sink got a request in another format")
	}
	body := p.body
	if c.gzip {
		body = compress(body)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return result{verdict: drop, kind: kindClient, detail: "the request can't be made"}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", p.contentType)
	req.Header.Set("User-Agent", "inkwall-operator")
	if c.gzip {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return transportError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	// The rest is discarded, so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	r := classifyHTTP(resp.StatusCode, p.otlp != nil, resp.Header.Get("Retry-After"), time.Now())
	if r.verdict == sent {
		if p.otlp != nil {
			r.rejected, r.detail = partialHTTP(raw)
		}
		return r
	}
	r.detail = strconv.Itoa(resp.StatusCode) + " " + escape(raw)
	return r
}

// partialHTTP reads OTLP's partial success from an ExportLogsServiceResponse;
// a body that isn't one (or is cut at maxResponse) is a full success.
func partialHTTP(raw []byte) (int, string) {
	var resp collogspb.ExportLogsServiceResponse
	if proto.Unmarshal(raw, &resp) != nil {
		return 0, ""
	}
	ps := resp.GetPartialSuccess()
	return int(min(ps.GetRejectedLogRecords(), 1<<31-1)), escape([]byte(ps.GetErrorMessage()))
}

// classifyHTTP maps a status to a verdict: the OTLP spec's retryable set
// for otlp sinks, plus 408 and 500 for json ones; 401 and 403 retried
// slowly (the one deviation from the spec); 413 split; any other 3xx, 4xx
// or 5xx refused.
func classifyHTTP(code int, otlp bool, retryAfter string, now time.Time) result {
	switch {
	case code >= 200 && code < 300:
		return result{verdict: sent}
	case code == http.StatusUnauthorized, code == http.StatusForbidden:
		return result{verdict: retrySlow, kind: kindAuth}
	case code == http.StatusTooManyRequests:
		return result{verdict: retry, kind: kindThrottled, after: parseRetryAfter(retryAfter, now)}
	case code == http.StatusBadGateway, code == http.StatusServiceUnavailable, code == http.StatusGatewayTimeout,
		!otlp && code == http.StatusInternalServerError:
		return result{verdict: retry, kind: kindServer, after: parseRetryAfter(retryAfter, now)}
	case !otlp && code == http.StatusRequestTimeout:
		return result{verdict: retry, kind: kindTimeout, after: parseRetryAfter(retryAfter, now)}
	case code == http.StatusRequestEntityTooLarge:
		return result{verdict: split, kind: kindClient}
	case code >= 500:
		return result{verdict: drop, kind: kindServer}
	}
	// 3xx (redirects are never followed), and the other 4xx.
	return result{verdict: drop, kind: kindClient}
}

// parseRetryAfter reads seconds or an HTTP date, capped at maxRetryAfter.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 {
			return 0
		}
		d = time.Duration(min(n, int64(maxRetryAfter/time.Second))) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), maxRetryAfter)
}

// transportError classes a failed connection or request.
func transportError(ctx context.Context, err error) result {
	if refused, ok := errors.AsType[*AddressRefusedError](err); ok {
		return result{verdict: retry, kind: kindNetwork, refused: refused.Class, detail: refused.Error()}
	}
	var (
		certErr    *tls.CertificateVerificationError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
		recordErr  tls.RecordHeaderError
		alertErr   tls.AlertError
		netErr     net.Error
	)
	switch {
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidErr),
		errors.As(err, &recordErr), errors.As(err, &alertErr), strings.Contains(err.Error(), "tls: "):
		return result{verdict: retry, kind: kindTLS, detail: "TLS: " + tlsClass(err)}
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil || errors.As(err, &netErr) && netErr.Timeout():
		return result{verdict: retry, kind: kindTimeout, detail: "timeout"}
	}
	return result{verdict: retry, kind: kindNetwork, detail: "connection failed"}
}

// tlsClass names a TLS failure without what the server sent.
func tlsClass(err error) string {
	var (
		unknownCA x509.UnknownAuthorityError
		hostErr   x509.HostnameError
		invalid   x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &unknownCA):
		return "certificate signed by an unknown authority"
	case errors.As(err, &hostErr):
		return "certificate not valid for the name"
	case errors.As(err, &invalid):
		return "certificate invalid or expired"
	}
	return "handshake failed"
}

// escape quotes at most maxDetail bytes of a response.
func escape(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	cut := raw[:min(len(raw), maxDetail)]
	return strconv.QuoteToASCII(string(cut))
}

func (c *httpClient) close() { c.transport.CloseIdleConnections() }

// maxGRPCResponse bounds an Export answer: a partial success's message
// can be long. Its odd value tells grpc-go's error for it apart from the
// same error a server sends for a request over its own limit (4 MiB by
// default), which is a refusal. Tests lower it.
var maxGRPCResponse = 4<<20 + 4093

// responseOverLimit reports grpc-go's error for an answer over
// maxGRPCResponse.
func responseOverLimit(st *status.Status) bool {
	m := st.Message()
	limit := strconv.Itoa(maxGRPCResponse)
	return st.Code() == codes.ResourceExhausted && strings.HasPrefix(m, "grpc: ") && strings.Contains(m, "larger than max") &&
		(strings.HasSuffix(m, " vs. "+limit+")") || strings.HasSuffix(m, "larger than max "+limit))
}

// grpcClient calls LogsService/Export: no proxy, the guarded dialer.
type grpcClient struct {
	conn *grpc.ClientConn
	logs collogspb.LogsServiceClient
	gzip bool
}

func newGRPCClient(tc transportConfig) (*grpcClient, error) {
	creds := insecure.NewCredentials()
	if !tc.insecure {
		creds = credentials.NewTLS(tc.tls)
	}
	conn, err := grpc.NewClient("passthrough:///"+tc.url,
		grpc.WithTransportCredentials(creds),
		grpc.WithNoProxy(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialContext(ctx, "tcp", addr)
		}),
		grpc.WithUserAgent("inkwall-operator"),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxGRPCResponse)),
	)
	if err != nil {
		return nil, err
	}
	return &grpcClient{conn: conn, logs: collogspb.NewLogsServiceClient(conn), gzip: tc.gzip}, nil
}

func (c *grpcClient) send(ctx context.Context, p payload, headers map[string]string) result {
	if p.otlp == nil {
		return mismatched("a gRPC sink got a request that isn't OTLP")
	}
	if len(headers) > 0 {
		md := metadata.MD{}
		for k, v := range headers {
			md.Set(strings.ToLower(k), v)
		}
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	var opts []grpc.CallOption
	if c.gzip {
		opts = append(opts, grpc.UseCompressor(grpcgzip.Name))
	}
	resp, err := c.logs.Export(ctx, p.otlp, opts...)
	if err == nil {
		ps := resp.GetPartialSuccess()
		return result{verdict: sent, rejected: int(min(ps.GetRejectedLogRecords(), 1<<31-1)), detail: escape([]byte(ps.GetErrorMessage()))}
	}
	st := status.Convert(err)
	if responseOverLimit(st) {
		// The client's own limit, on the server's answer: the server took
		// the request. Sending it again would duplicate it.
		return result{verdict: sent, detail: "the sink's answer was over the response limit"}
	}
	return classifyGRPC(st, p.size)
}

// classifyGRPC maps a status: the OTLP spec's retryable codes, with
// RESOURCE_EXHAUSTED retried only with RetryInfo, split when the request is
// large, and throttled otherwise; UNAUTHENTICATED and PERMISSION_DENIED
// retried slowly; any other code refused.
func classifyGRPC(st *status.Status, size int) result {
	detail := st.Code().String()
	switch st.Code() {
	case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled:
		// Mostly the client's own (a connection that failed, a timeout):
		// their messages name the address dialed, which stays out of status.
	default:
		if m := st.Message(); m != "" {
			detail += " " + escape([]byte(m))
		}
	}
	var after time.Duration
	hasRetryInfo := false
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok {
			hasRetryInfo = true
			after = min(max(ri.GetRetryDelay().AsDuration(), 0), maxRetryAfter)
		}
	}
	r := result{detail: detail, after: after}
	if class, ok := refusedIn(st.Message()); ok {
		r.verdict, r.kind, r.refused, r.detail = retry, kindNetwork, class, "the sink's address is refused: "+class
		return r
	}
	switch st.Code() {
	case codes.OK:
		r.verdict, r.kind = sent, ""
	case codes.Unavailable:
		r.verdict, r.kind = retry, kindNetwork
		if strings.Contains(st.Message(), "tls:") || strings.Contains(st.Message(), "x509:") ||
			strings.Contains(st.Message(), "authentication handshake failed") {
			r.kind, r.detail = kindTLS, "Unavailable TLS: handshake failed"
		}
	case codes.DeadlineExceeded:
		r.verdict, r.kind = retry, kindTimeout
	case codes.Aborted, codes.Canceled, codes.OutOfRange, codes.DataLoss:
		r.verdict, r.kind = retry, kindServer
	case codes.ResourceExhausted:
		switch {
		case hasRetryInfo:
			r.verdict, r.kind = retry, kindThrottled
		case size > splitOver:
			r.verdict, r.kind = split, kindClient
		default:
			r.verdict, r.kind = retry, kindThrottled
		}
	case codes.Unauthenticated, codes.PermissionDenied:
		r.verdict, r.kind = retrySlow, kindAuth
	case codes.Internal, codes.Unknown:
		r.verdict, r.kind = drop, kindServer
	default:
		r.verdict, r.kind = drop, kindClient
	}
	return r
}

// refusedIn finds the dialer guard's refusal in a gRPC status message.
func refusedIn(msg string) (string, bool) {
	const marker = "the sink's address is refused: "
	_, rest, ok := strings.Cut(msg, marker)
	if !ok {
		return "", false
	}
	for _, class := range []string{"loopback", "unspecified", "link-local", "metadata"} {
		if strings.HasPrefix(rest, class) {
			return class, true
		}
	}
	return "", false
}

func (c *grpcClient) close() { _ = c.conn.Close() }

// errNoPort is a gRPC endpoint without its port.
var errNoPort = errors.New("the gRPC endpoint needs a port: grpcs://host:port")

// grpcTarget is host:port of a grpcs:// or grpc:// endpoint.
func grpcTarget(endpoint string) (string, error) {
	_, rest, ok := strings.Cut(endpoint, "://")
	if !ok {
		return "", fmt.Errorf("endpoint %q: no scheme", endpoint)
	}
	host, port, err := net.SplitHostPort(rest)
	if err != nil || host == "" || port == "" {
		return "", errNoPort
	}
	return rest, nil
}
