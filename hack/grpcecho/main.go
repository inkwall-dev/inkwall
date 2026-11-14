// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command grpcecho is a gRPC server and client for the end-to-end tests of
// gRPC streams (#315, #317). The service, inkwall.test.Echo, has no .proto:
// its messages are google.protobuf.StringValue (field 1, text).
//
//   - Collect, a client stream: the server reads every message, and answers
//     how many it got.
//   - Chat, a bidirectional call: the server echoes each message as it comes;
//     the client waits for each echo before it sends the next, so a proxy
//     that holds the call until the client ends its side stalls it.
//   - Stream, a server stream: the server sends the request's text split at
//     "|", one message each.
//
// The server logs each message it gets ("got: TEXT"), so a test can tell a
// message never reached it.
//
//	grpcecho serve -listen :50051
//	grpcecho collect -authority grpc.example.com 127.0.0.1:8080 hello world "1' OR '1'='1' -- "
//	grpcecho chat -authority grpc.example.com 127.0.0.1:8080 hello world
//	grpcecho stream -authority grpc.example.com 127.0.0.1:8080 'hello|world'
//
// A client prints the messages it got back, one per line, then the call's
// status code (OK, PermissionDenied, ...).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const service = "inkwall.test.Echo"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	switch cmd {
	case "serve":
		listen := fs.String("listen", ":50051", "the address to serve on (h2c)")
		_ = fs.Parse(args)
		if err := serve(*listen); err != nil {
			log.Fatal(err)
		}
	case "collect", "chat", "stream":
		authority := fs.String("authority", "", "the :authority to send")
		_ = fs.Parse(args)
		if fs.NArg() < 1 {
			usage()
		}
		got, err := call(cmd, fs.Arg(0), *authority, fs.Args()[1:])
		for _, g := range got {
			fmt.Println(g)
		}
		st, ok := status.FromError(err)
		if !ok {
			fmt.Fprintln(os.Stderr, "grpcecho:", err)
			os.Exit(1)
		}
		if st.Message() != "" && st.Code() != 0 {
			fmt.Fprintln(os.Stderr, "grpcecho:", st.Message())
		}
		fmt.Println(st.Code())
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: grpcecho serve [-listen ADDR] | grpcecho collect|chat|stream [-authority HOST] HOST:PORT MESSAGE...")
	os.Exit(2)
}

// echoServer is the service's implementation; the desc below routes to it.
type echoServer struct{}

func (echoServer) collect(stream grpc.ServerStream) error {
	n := 0
	for {
		m := new(wrapperspb.StringValue)
		err := stream.RecvMsg(m)
		if errors.Is(err, io.EOF) {
			return stream.SendMsg(wrapperspb.String(strconv.Itoa(n) + " messages"))
		}
		if err != nil {
			return err
		}
		log.Printf("got: %s", m.GetValue())
		n++
	}
}

func (echoServer) chat(stream grpc.ServerStream) error {
	for {
		m := new(wrapperspb.StringValue)
		err := stream.RecvMsg(m)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		log.Printf("got: %s", m.GetValue())
		if err := stream.SendMsg(wrapperspb.String("echo: " + m.GetValue())); err != nil {
			return err
		}
	}
}

func (echoServer) stream(stream grpc.ServerStream) error {
	m := new(wrapperspb.StringValue)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	log.Printf("got: %s", m.GetValue())
	for _, part := range strings.Split(m.GetValue(), "|") {
		if err := stream.SendMsg(wrapperspb.String(part)); err != nil {
			return err
		}
		// Each message in its own DATA frame, as a real stream sends them.
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

var desc = grpc.ServiceDesc{
	ServiceName: service,
	HandlerType: (*any)(nil),
	Streams: []grpc.StreamDesc{
		{StreamName: "Collect", ClientStreams: true, Handler: func(_ any, s grpc.ServerStream) error { return echoServer{}.collect(s) }},
		{StreamName: "Chat", ClientStreams: true, ServerStreams: true, Handler: func(_ any, s grpc.ServerStream) error { return echoServer{}.chat(s) }},
		{StreamName: "Stream", ServerStreams: true, Handler: func(_ any, s grpc.ServerStream) error { return echoServer{}.stream(s) }},
	},
}

func serve(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	s.RegisterService(&desc, echoServer{})
	log.Printf("serving %s", service)
	return s.Serve(l)
}

// call makes one call and returns the messages it got back and its error.
func call(method, target, authority string, msgs []string) ([]string, error) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if authority != "" {
		opts = append(opts, grpc.WithAuthority(authority))
	}
	conn, err := grpc.NewClient("passthrough:///"+target, opts...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var sd grpc.StreamDesc
	switch method {
	case "collect":
		sd = desc.Streams[0]
	case "chat":
		sd = desc.Streams[1]
	default:
		sd = desc.Streams[2]
	}
	stream, err := conn.NewStream(ctx, &sd, "/"+service+"/"+sd.StreamName)
	if err != nil {
		return nil, err
	}
	var got []string
	recv := func() error {
		m := new(wrapperspb.StringValue)
		if err := stream.RecvMsg(m); err != nil {
			return err
		}
		got = append(got, m.GetValue())
		return nil
	}
	switch method {
	case "chat":
		// Each message waits for its echo: the client never ends its side
		// before the server answers.
		for _, m := range msgs {
			if err := stream.SendMsg(wrapperspb.String(m)); err != nil {
				break
			}
			if err := recv(); err != nil {
				return got, err
			}
		}
		_ = stream.CloseSend()
	case "collect":
		for _, m := range msgs {
			if err := stream.SendMsg(wrapperspb.String(m)); err != nil {
				break
			}
			// Each message in its own DATA frame.
			time.Sleep(50 * time.Millisecond)
		}
		_ = stream.CloseSend()
	default:
		_ = stream.SendMsg(wrapperspb.String(strings.Join(msgs, "|")))
		_ = stream.CloseSend()
	}
	for {
		if err := recv(); err != nil {
			if errors.Is(err, io.EOF) {
				return got, nil
			}
			return got, err
		}
	}
}
