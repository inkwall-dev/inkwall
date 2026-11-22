// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package compile compiles a FileDescriptorSet into the schema engines read
// gRPC messages with (design 0013 §5.1, §5.2): the operator runs it on a
// policy's descriptor set, so that engines never parse descriptors.
package compile

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	bundlev1 "github.com/inkwall-dev/inkwall/api/bundle/v1"
	"github.com/inkwall-dev/inkwall/pkg/grpcschema"
)

// Bounds of the source (design 0013 §5.4): a ConfigMap holds at most 1 MiB,
// and a gzipped set decompresses to at most 8 MiB.
const (
	MaxSourceBytes   = 1 << 20
	MaxGunzipBytes   = 8 << 20
	maxNesting       = 100 // proto.UnmarshalOptions.RecursionLimit: nested declarations
	anyFullName      = "google.protobuf.Any"
	gzipMagic0       = 0x1f
	gzipMagic1       = 0x8b
	typeURLFieldName = "type_url"
	valueFieldName   = "value"
)

// Compile compiles data, a serialized FileDescriptorSet, raw or gzipped,
// into a schema whose source is source ("namespace/configmap/key"). The
// set must include its imports and describe at least one service. An error
// says what failed, naming the file or type where there is one.
func Compile(data []byte, source string) (s *bundlev1.GRPCSchema, err error) {
	defer func() {
		// protodesc on a hostile set: a panic is a set that isn't valid.
		if r := recover(); r != nil {
			s, err = nil, fmt.Errorf("not a valid descriptor set: %v", r)
		}
	}()
	set, err := decode(data)
	if err != nil {
		return nil, err
	}
	for _, f := range set.GetFile() {
		f.SourceCodeInfo = nil
	}
	files, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, err
	}
	s, err = compileFiles(files)
	if err != nil {
		return nil, err
	}
	s.Source = source
	return s, nil
}

// decode reads a FileDescriptorSet, gunzipping it first if it is gzip.
func decode(data []byte) (*descriptorpb.FileDescriptorSet, error) {
	if len(data) > MaxSourceBytes {
		return nil, fmt.Errorf("%d bytes, over %d", len(data), MaxSourceBytes)
	}
	if len(data) >= 2 && data[0] == gzipMagic0 && data[1] == gzipMagic1 {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		out, err := io.ReadAll(io.LimitReader(zr, MaxGunzipBytes+1))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		if len(out) > MaxGunzipBytes {
			return nil, fmt.Errorf("gunzipped over %d bytes", MaxGunzipBytes)
		}
		data = out
	}
	var set descriptorpb.FileDescriptorSet
	if err := (proto.UnmarshalOptions{RecursionLimit: maxNesting}).Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("not a FileDescriptorSet, or declarations nested too deep: %w", err)
	}
	if len(set.GetFile()) == 0 {
		return nil, errors.New("no file: not a FileDescriptorSet")
	}
	return &set, nil
}

// compiler holds a compilation's messages, by full name.
type compiler struct {
	files      *protoregistry.Files
	extensions map[protoreflect.FullName][]protoreflect.ExtensionDescriptor
	kept       map[protoreflect.FullName]protoreflect.MessageDescriptor
	queue      []protoreflect.MessageDescriptor
	hasAny     bool
}

func compileFiles(files *protoregistry.Files) (*bundlev1.GRPCSchema, error) {
	c := &compiler{
		files:      files,
		extensions: map[protoreflect.FullName][]protoreflect.ExtensionDescriptor{},
		kept:       map[protoreflect.FullName]protoreflect.MessageDescriptor{},
	}
	type method struct {
		path          string
		input, output protoreflect.MessageDescriptor
	}
	var methods []method
	var all []protoreflect.MessageDescriptor
	files.RangeFiles(func(f protoreflect.FileDescriptor) bool {
		c.addExtensions(f.Extensions())
		all = appendMessages(all, f.Messages(), c)
		for i := range f.Services().Len() {
			svc := f.Services().Get(i)
			for j := range svc.Methods().Len() {
				m := svc.Methods().Get(j)
				methods = append(methods, method{"/" + string(svc.FullName()) + "/" + string(m.Name()), m.Input(), m.Output()})
			}
		}
		return true
	})
	if len(methods) == 0 {
		return nil, errors.New("no service: the set describes no method to read messages of")
	}
	if len(methods) > grpcschema.MaxMethods {
		return nil, fmt.Errorf("%d methods, over %d", len(methods), grpcschema.MaxMethods)
	}
	for _, m := range methods {
		if len(m.path) > grpcschema.MaxFullName {
			return nil, fmt.Errorf("method %.60s: path over %d bytes", m.path, grpcschema.MaxFullName)
		}
		c.keep(m.input)
		c.keep(m.output)
	}
	// Every message reachable from a method, through fields and extensions.
	for len(c.queue) > 0 {
		md := c.queue[0]
		c.queue = c.queue[1:]
		c.walk(md)
	}
	// An Any may name any message of the set.
	if c.hasAny {
		for _, md := range all {
			c.keep(md)
		}
		for len(c.queue) > 0 {
			md := c.queue[0]
			c.queue = c.queue[1:]
			c.walk(md)
		}
	}
	if len(c.kept) > grpcschema.MaxMessages {
		return nil, fmt.Errorf("%d messages, over %d", len(c.kept), grpcschema.MaxMessages)
	}

	names := make([]protoreflect.FullName, 0, len(c.kept))
	for n := range c.kept {
		names = append(names, n)
	}
	slices.Sort(names)
	index := make(map[protoreflect.FullName]uint32, len(names))
	for i, n := range names {
		index[n] = uint32(i)
	}
	out := &bundlev1.GRPCSchema{}
	total := 0
	for _, n := range names {
		md := c.kept[n]
		msg, err := c.message(md, index)
		if err != nil {
			return nil, fmt.Errorf("message %s: %w", n, err)
		}
		if total += len(msg.Fields); total > grpcschema.MaxFields {
			return nil, fmt.Errorf("over %d fields in the messages the methods read", grpcschema.MaxFields)
		}
		out.Messages = append(out.Messages, msg)
	}
	slices.SortFunc(methods, func(a, b method) int { return cmp.Compare(a.path, b.path) })
	for _, m := range methods {
		out.Methods = append(out.Methods, &bundlev1.GRPCMethod{Path: m.path, Input: index[m.input.FullName()], Output: index[m.output.FullName()]})
	}
	content, err := proto.MarshalOptions{Deterministic: true}.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(content) > grpcschema.MaxCompiledBytes {
		return nil, fmt.Errorf("compiled to %d bytes, over %d", len(content), grpcschema.MaxCompiledBytes)
	}
	sum := sha256.Sum256(content)
	out.Id = hex.EncodeToString(sum[:])
	return out, nil
}

// appendMessages appends msgs and their nested messages to all, and
// records their nested extensions.
func appendMessages(all []protoreflect.MessageDescriptor, msgs protoreflect.MessageDescriptors, c *compiler) []protoreflect.MessageDescriptor {
	for i := range msgs.Len() {
		md := msgs.Get(i)
		all = append(all, md)
		c.addExtensions(md.Extensions())
		all = appendMessages(all, md.Messages(), c)
	}
	return all
}

func (c *compiler) addExtensions(exts protoreflect.ExtensionDescriptors) {
	for i := range exts.Len() {
		x := exts.Get(i)
		target := x.ContainingMessage().FullName()
		c.extensions[target] = append(c.extensions[target], x)
	}
}

// keep adds md to the messages kept, to walk.
func (c *compiler) keep(md protoreflect.MessageDescriptor) {
	if _, ok := c.kept[md.FullName()]; ok {
		return
	}
	c.kept[md.FullName()] = md
	c.queue = append(c.queue, md)
}

// walk keeps the types of md's fields and extensions.
func (c *compiler) walk(md protoreflect.MessageDescriptor) {
	if isAny(md) {
		c.hasAny = true
	}
	fields := md.Fields()
	for i := range fields.Len() {
		if t := fields.Get(i).Message(); t != nil {
			c.keep(t)
		}
	}
	for _, x := range c.extensions[md.FullName()] {
		if t := x.Message(); t != nil {
			c.keep(t)
		}
	}
}

// isAny reports whether md is google.protobuf.Any as protobuf defines it:
// a string type_url (1) and a bytes value (2).
func isAny(md protoreflect.MessageDescriptor) bool {
	if md.FullName() != anyFullName {
		return false
	}
	u, v := md.Fields().ByNumber(1), md.Fields().ByNumber(2)
	return u != nil && v != nil && u.Kind() == protoreflect.StringKind && v.Kind() == protoreflect.BytesKind &&
		u.Name() == typeURLFieldName && v.Name() == valueFieldName && !u.IsList() && !v.IsList()
}

// message compiles md, whose kept types are numbered by index.
func (c *compiler) message(md protoreflect.MessageDescriptor, index map[protoreflect.FullName]uint32) (*bundlev1.GRPCMessage, error) {
	if len(md.FullName()) > grpcschema.MaxFullName {
		return nil, fmt.Errorf("full name over %d bytes", grpcschema.MaxFullName)
	}
	out := &bundlev1.GRPCMessage{FullName: string(md.FullName()), Any: isAny(md)}
	add := func(fd protoreflect.FieldDescriptor, name string) error {
		f := &bundlev1.GRPCField{Number: uint32(fd.Number()), Name: name, Repeated: fd.Cardinality() == protoreflect.Repeated} // #nosec G115 -- a declared number is positive
		switch fd.Kind() {
		case protoreflect.StringKind:
			f.Kind = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_STRING
		case protoreflect.BytesKind:
			f.Kind = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_BYTES
		case protoreflect.MessageKind:
			f.Kind = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_MESSAGE
			f.Message = index[fd.Message().FullName()]
		case protoreflect.GroupKind:
			f.Kind = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_GROUP
			f.Message = index[fd.Message().FullName()]
		case protoreflect.BoolKind, protoreflect.EnumKind,
			protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Uint32Kind, protoreflect.Uint64Kind,
			protoreflect.Sint32Kind, protoreflect.Sint64Kind:
			f.Kind = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_VARINT
		case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
			f.Kind = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_FIXED32
		case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
			f.Kind = bundlev1.GRPCFieldKind_GRPC_FIELD_KIND_FIXED64
		default:
			return fmt.Errorf("field %s: kind %v", name, fd.Kind())
		}
		out.Fields = append(out.Fields, f)
		return nil
	}
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if len(fd.Name()) > grpcschema.MaxFieldName {
			return nil, fmt.Errorf("field %.40s: name over %d bytes", fd.Name(), grpcschema.MaxFieldName)
		}
		if err := add(fd, string(fd.Name())); err != nil {
			return nil, err
		}
	}
	for _, x := range c.extensions[md.FullName()] {
		if len(x.FullName()) > grpcschema.MaxFullName {
			return nil, fmt.Errorf("extension %.40s: name over %d bytes", x.FullName(), grpcschema.MaxFullName)
		}
		if err := add(x, "["+string(x.FullName())+"]"); err != nil {
			return nil, err
		}
	}
	if len(out.Fields) > grpcschema.MaxMessageFields {
		return nil, fmt.Errorf("%d fields, over %d", len(out.Fields), grpcschema.MaxMessageFields)
	}
	slices.SortFunc(out.Fields, func(a, b *bundlev1.GRPCField) int { return cmp.Compare(a.Number, b.Number) })
	for i := 1; i < len(out.Fields); i++ {
		if out.Fields[i].Number == out.Fields[i-1].Number {
			return nil, fmt.Errorf("number %d is both %s and %s", out.Fields[i].Number, out.Fields[i-1].Name, out.Fields[i].Name)
		}
	}
	return out, nil
}

// Cache compiles each distinct descriptor set once (design 0013 §5.1): by
// the SHA-256 of the ConfigMap value, errors too. It is safe for concurrent
// use.
type Cache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]entry
}

type entry struct {
	schema *bundlev1.GRPCSchema // without its source
	err    error
}

// NewCache returns an empty cache.
func NewCache() *Cache { return &Cache{entries: map[[sha256.Size]byte]entry{}} }

// Compile is Compile, cached; the schema returned is the caller's. It
// returns the key the value is cached under, for Retain.
func (c *Cache) Compile(data []byte, source string) (*bundlev1.GRPCSchema, [sha256.Size]byte, error) {
	key := sha256.Sum256(data)
	if c == nil {
		s, err := Compile(data, source)
		return s, key, err
	}
	c.mu.Lock()
	e, ok := c.entries[key]
	c.mu.Unlock()
	if !ok {
		e.schema, e.err = Compile(data, "")
		c.mu.Lock()
		c.entries[key] = e
		c.mu.Unlock()
	}
	if e.err != nil {
		return nil, key, e.err
	}
	s := proto.CloneOf(e.schema)
	s.Source = source
	return s, key, nil
}

// Retain drops the entries whose keys used doesn't hold: those no policy
// named in the latest build.
func (c *Cache) Retain(used map[[sha256.Size]byte]bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		if !used[k] {
			delete(c.entries, k)
		}
	}
}

// Len returns the number of entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
