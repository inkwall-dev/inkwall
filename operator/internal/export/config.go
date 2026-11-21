// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	wafv1alpha1 "github.com/inkwall-dev/inkwall/operator/api/v1alpha1"
)

// Defaults of a sink (design 0010 §4.1).
const (
	defaultMaxEvents   = 500
	defaultMaxDelay    = 5 * time.Second
	defaultMaxInFlight = 4
	defaultTimeout     = 10 * time.Second
)

// sinkConfig is a sink as it runs: the InkwallConfig's entry with its
// Secrets read. err says why it can't start (never a Secret's value).
type sinkConfig struct {
	name      string
	format    format
	transport transportConfig
	// key fingerprints the transport: a change (endpoint, CA, client
	// certificate, URL Secret) rebuilds it.
	key         string
	headers     map[string]string
	view        view
	maxEvents   int
	maxInFlight int
	maxDelay    time.Duration
	timeout     time.Duration
	deny, log   bool
	namespaces  map[string]bool // nil: every policy, and none
	plaintext   bool
	err         error
}

// configError is why a sink can't start: ExportConfigInvalid.
type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

func invalid(format string, args ...any) error { return &configError{fmt.Sprintf(format, args...)} }

// urlPattern is json.url's check (design 0010 §4.5), for a URL read from
// urlSecretRef: no user info, no space.
var urlPattern = regexp.MustCompile(`^https?://[^/?#@\s]+([/?]\S*)?$`)

// Header names the transports own (design 0010 §4.2).
var ownedHeaders = []string{"host", "content-type", "content-length", "content-encoding", "transfer-encoding", "connection", "te", "trailer", "upgrade"}

// checkHeader refuses a header name that isn't an HTTP token or that the
// transport owns.
func checkHeader(name string, grpc bool) error {
	if !httpguts.ValidHeaderFieldName(name) {
		return errors.New("not an HTTP header name")
	}
	l := strings.ToLower(name)
	if slices.Contains(ownedHeaders, l) || strings.HasPrefix(l, "proxy-") {
		return errors.New("the transport sets it")
	}
	if grpc && (strings.HasPrefix(l, "grpc-") || strings.HasSuffix(l, "-bin")) {
		return errors.New("reserved in gRPC metadata")
	}
	return nil
}

// resolve reads the sinks of spec, with their Secrets in namespace.
func resolve(ctx context.Context, c client.Reader, namespace, clusterID string, spec *wafv1alpha1.ExportSpec) []*sinkConfig {
	if spec == nil {
		return nil
	}
	out := make([]*sinkConfig, 0, len(spec.Sinks))
	for i := range spec.Sinks {
		s := &spec.Sinks[i]
		sc := &sinkConfig{name: s.Name}
		sc.err = sc.fill(ctx, c, namespace, clusterID, spec.ClusterName, s)
		out = append(out, sc)
	}
	return out
}

func (sc *sinkConfig) fill(ctx context.Context, c client.Reader, namespace, clusterID, clusterName string, s *wafv1alpha1.EventSink) error {
	sc.view = newView(clusterID, clusterName, s.Omit)
	sc.maxEvents = int(ptrOr(s.Batch.MaxEvents, defaultMaxEvents))
	sc.maxInFlight = int(ptrOr(s.Batch.MaxInFlight, defaultMaxInFlight))
	sc.maxDelay, sc.timeout = defaultMaxDelay, defaultTimeout
	if s.Batch.MaxDelay != nil {
		sc.maxDelay = s.Batch.MaxDelay.Duration
	}
	if s.Timeout != nil {
		sc.timeout = s.Timeout.Duration
	}
	// The API server checks the bounds; an object written before them
	// stays within too.
	sc.maxEvents = min(max(sc.maxEvents, 1), 1000)
	sc.maxInFlight = min(max(sc.maxInFlight, 1), 4)
	sc.maxDelay = min(max(sc.maxDelay, 100*time.Millisecond), time.Minute)
	sc.timeout = min(max(sc.timeout, time.Second), time.Minute)
	sc.deny, sc.log = len(s.Filter.Actions) == 0, len(s.Filter.Actions) == 0
	for _, a := range s.Filter.Actions {
		switch a {
		case wafv1alpha1.ExportDeny:
			sc.deny = true
		case wafv1alpha1.ExportLog:
			sc.log = true
		}
	}
	if len(s.Filter.PolicyNamespaces) > 0 {
		sc.namespaces = map[string]bool{}
		for _, ns := range s.Filter.PolicyNamespaces {
			sc.namespaces[string(ns)] = true
		}
	}
	tc := transportConfig{gzip: s.Compression != wafv1alpha1.CompressionNone, insecure: s.Insecure}
	var endpoint string
	switch {
	case s.OTLP != nil:
		endpoint = s.OTLP.Endpoint
		switch {
		case strings.HasPrefix(endpoint, "grpcs://"), strings.HasPrefix(endpoint, "grpc://"):
			sc.format, tc.grpc = formatOTLPGRPC, true
			target, err := grpcTarget(endpoint)
			if err != nil {
				return invalid("sink %s: %v", s.Name, err)
			}
			tc.url = target
		default:
			sc.format, tc.url = formatOTLPHTTP, endpoint
		}
	case s.JSON != nil:
		sc.format = formatJSONLines
		if s.JSON.Framing == wafv1alpha1.JSONArray {
			sc.format = formatJSONArray
		}
		endpoint = s.JSON.URL
		if ref := s.JSON.URLSecretRef; ref != nil {
			sec, err := secret(ctx, c, namespace, ref.Name)
			if err != nil {
				return err
			}
			v, ok := sec.Data[ref.Key]
			if !ok {
				return invalid("the Secret %s has no key %s", ref.Name, ref.Key)
			}
			endpoint = strings.TrimSpace(string(v))
			// The URL stays out of every message: it holds a token.
			if len(endpoint) > 2048 || !urlPattern.MatchString(endpoint) {
				return invalid("the URL in the Secret %s, key %s, isn't an https:// or http:// URL without user info", ref.Name, ref.Key)
			}
		}
		tc.url = endpoint
	default:
		return invalid("sink %s has neither otlp nor json", s.Name)
	}
	sc.plaintext = strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "grpc://")
	if sc.plaintext && !s.Insecure {
		return invalid("sink %s: a plaintext endpoint needs insecure: true", s.Name)
	}
	if sc.plaintext && s.HeadersSecretRef != nil {
		return invalid("sink %s: a plaintext endpoint can't have headersSecretRef", s.Name)
	}
	tc.insecure = sc.plaintext
	host := hostOf(endpoint)
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%t\x00%t\x00", sc.format, tc.url, tc.insecure, tc.gzip)
	if !sc.plaintext {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		if s.TLS != nil && s.TLS.ServerName != "" {
			cfg.ServerName = s.TLS.ServerName
		}
		fmt.Fprintf(h, "%s\x00", cfg.ServerName)
		if s.TLS != nil && s.TLS.CASecretRef != nil {
			sec, err := secret(ctx, c, namespace, s.TLS.CASecretRef.Name)
			if err != nil {
				return err
			}
			pem, ok := sec.Data["ca.crt"]
			if !ok {
				return invalid("the Secret %s has no key ca.crt", s.TLS.CASecretRef.Name)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return invalid("the Secret %s's ca.crt holds no PEM certificate", s.TLS.CASecretRef.Name)
			}
			cfg.RootCAs = pool
			h.Write(pem)
			h.Write([]byte{0})
		}
		if s.TLS != nil && s.TLS.ClientCertificateSecretRef != nil {
			name := s.TLS.ClientCertificateSecretRef.Name
			sec, err := secret(ctx, c, namespace, name)
			if err != nil {
				return err
			}
			cert, err := tls.X509KeyPair(sec.Data[corev1.TLSCertKey], sec.Data[corev1.TLSPrivateKeyKey])
			if err != nil {
				return invalid("the Secret %s doesn't hold a client certificate and its key (tls.crt, tls.key)", name)
			}
			cfg.Certificates = []tls.Certificate{cert}
			h.Write(sec.Data[corev1.TLSCertKey])
			h.Write(sec.Data[corev1.TLSPrivateKeyKey])
		}
		tc.tls = cfg
	}
	sc.transport = tc
	sc.key = hex.EncodeToString(h.Sum(nil))
	if ref := s.HeadersSecretRef; ref != nil {
		sec, err := secret(ctx, c, namespace, ref.Name)
		if err != nil {
			return err
		}
		sc.headers = make(map[string]string, len(sec.Data))
		for k, v := range sec.Data {
			if err := checkHeader(k, tc.grpc); err != nil {
				return invalid("the Secret %s: header %q refused: %v", ref.Name, k, err)
			}
			val := strings.TrimSpace(string(v))
			if !httpguts.ValidHeaderFieldValue(val) {
				return invalid("the Secret %s: the value of header %q isn't a valid header value", ref.Name, k)
			}
			sc.headers[k] = val
		}
	}
	return nil
}

func ptrOr(p *int32, d int32) int32 {
	if p == nil {
		return d
	}
	return *p
}

func hostOf(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// secret reads a Secret of the operator's namespace: the references carry
// no namespace (design 0010 §4.2).
func secret(ctx context.Context, c client.Reader, namespace, name string) (*corev1.Secret, error) {
	var s corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &s)
	switch {
	case apierrors.IsNotFound(err):
		return nil, invalid("the Secret %s doesn't exist in %s", name, namespace)
	case err != nil:
		return nil, fmt.Errorf("the Secret %s: %w", name, err)
	}
	return &s, nil
}

// takes reports whether the sink takes the event: its action, and its
// policy's namespace when filtered by namespace.
func (sc *sinkConfig) takes(it item) bool {
	switch actionName(it.ev.GetAction()) {
	case "deny":
		if !sc.deny {
			return false
		}
	case "log":
		if !sc.log {
			return false
		}
	default:
		// An action the filter can't name: only sinks taking both.
		if !sc.deny || !sc.log {
			return false
		}
	}
	if sc.namespaces == nil {
		return true
	}
	if it.policy == "" {
		return false
	}
	ns, _ := splitPolicy(it.policy)
	return sc.namespaces[ns]
}
