// Copyright 2026 The Inkwall Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcschema holds a policy's gRPC schema as the engine reads
// messages with it (design 0013 §5, §6): the compiled form the operator puts
// in the bundle (bundlev1.GRPCSchema, which pkg/grpcschema/load reads),
// checked and indexed. The engine never parses descriptors: New checks
// integers and short strings only, so that a schema that passes can be
// walked without further checks.
package grpcschema

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protowire"
)

// Bounds of a compiled schema (design 0013 §5.4), which the operator's
// compiler and New both check.
const (
	MaxMethods         = 4096
	MaxMessages        = 16384
	MaxFields          = 65536
	MaxMessageFields   = 4096
	MaxFieldName       = 128
	MaxFullName        = 512
	MaxCompiledBytes   = 1 << 20
	maxExtensionName   = MaxFullName + 2 // "[" full name "]"
	maxDenseMultiplier = 2
)

// Kind is how a field's value is read: the values of
// bundlev1.GRPCFieldKind.
type Kind uint8

// The kinds of bundlev1.GRPCFieldKind.
const (
	KindString Kind = iota + 1
	KindBytes
	KindMessage
	KindGroup
	KindVarint
	KindFixed32
	KindFixed64
)

// Field is a field of a message type.
type Field struct {
	Number protowire.Number
	// Name is the proto name, or "[package.extension]".
	Name string
	Kind Kind
	// Message is the type of a KindMessage or KindGroup field.
	Message *Message
	// Repeated: a repeated number may come packed.
	Repeated bool
	// path is the last path built for the field (Path).
	path atomic.Pointer[path]
}

type path struct{ prefix, path string }

// Path returns the field's path under prefix, the path of its message:
// prefix + "." + Name, or Name at the top. The last one built is kept, so
// that a field read under the same prefix again, as the fields of
// repeated messages are, costs nothing.
func (f *Field) Path(prefix string) string {
	if prefix == "" {
		return f.Name
	}
	if p := f.path.Load(); p != nil && p.prefix == prefix {
		return p.path
	}
	p := prefix + "." + f.Name
	f.path.Store(&path{prefix, p})
	return p
}

// Message is a message type.
type Message struct {
	FullName string
	// Any: google.protobuf.Any, whose value is read as the type its
	// type_url names.
	Any    bool
	fields []Field
	// dense[n] is the index in fields of number n, plus one (0: none),
	// when the largest number is small enough; else fields are searched.
	dense []uint16
}

// Field returns the field numbered num, or nil when t has none.
func (t *Message) Field(num protowire.Number) *Field {
	if t.dense != nil {
		if num >= 0 && int(num) < len(t.dense) {
			if i := t.dense[num]; i != 0 {
				return &t.fields[i-1]
			}
		}
		return nil
	}
	i := sort.Search(len(t.fields), func(i int) bool { return t.fields[i].Number >= num })
	if i == len(t.fields) || t.fields[i].Number != num {
		return nil
	}
	return &t.fields[i]
}

// Fields returns how many fields t has.
func (t *Message) Fields() int { return len(t.fields) }

// FieldAt returns t's i-th field, by number.
func (t *Message) FieldAt(i int) *Field { return &t.fields[i] }

// Schema is a loaded schema. It is immutable and safe for concurrent use.
type Schema struct {
	id, source string
	messages   []Message
	methods    map[string]*Message
	byName     map[string]*Message
	size       int
}

// ID is the schema's id, the hash the bundle names it by.
func (s *Schema) ID() string { return s.id }

// Source is where its descriptor set came from: "namespace/configmap/key".
func (s *Schema) Source() string { return s.source }

// Methods is how many methods it describes.
func (s *Schema) Methods() int { return len(s.methods) }

// Size is its compiled size in bytes.
func (s *Schema) Size() int { return s.size }

// Method returns the input type of the method a call's path names
// ("/package.Service/Method", without a query), or nil when the schema
// doesn't describe it. s may be nil: no schema describes nothing.
func (s *Schema) Method(path string) *Message {
	if s == nil {
		return nil
	}
	return s.methods[path]
}

// Message returns the message type of a full name ("package.Message"), for
// an Any's type_url, or nil when the schema doesn't have it.
func (s *Schema) Message(fullName string) *Message {
	if s == nil {
		return nil
	}
	return s.byName[fullName]
}

// AnyType returns the message type an Any's type_url names: the part after
// its last '/' ("type.googleapis.com/package.Message"), or nil.
func (s *Schema) AnyType(typeURL string) *Message {
	if i := strings.LastIndexByte(typeURL, '/'); i >= 0 {
		typeURL = typeURL[i+1:]
	}
	return s.Message(typeURL)
}

// Def is a compiled schema as plain data (bundlev1.GRPCSchema, which
// pkg/grpcschema/load reads): what New checks and indexes. The package
// doesn't import the bundle, so that the reader (pkg/grpcwire) links no
// protobuf runtime.
type Def struct {
	ID, Source string
	// Size is the compiled size in bytes.
	Size     int
	Methods  []MethodDef
	Messages []MessageDef
}

// MethodDef is a method: its path, and its input and output types, indexes
// into Def.Messages.
type MethodDef struct {
	Path          string
	Input, Output uint32
}

// MessageDef is a message type.
type MessageDef struct {
	FullName string
	Any      bool
	Fields   []FieldDef
}

// FieldDef is a field: Message, for KindMessage and KindGroup only, is an
// index into Def.Messages.
type FieldDef struct {
	Number   uint32
	Name     string
	Kind     Kind
	Message  uint32
	Repeated bool
}

// New checks a compiled schema and indexes it. An error means the schema
// can't be read with: the operator compiles only schemas that pass, so the
// bundle carrying it is invalid.
func New(d Def) (*Schema, error) {
	if d.ID == "" {
		return nil, errors.New("no id")
	}
	if d.Size > MaxCompiledBytes {
		return nil, fmt.Errorf("%d bytes, over %d", d.Size, MaxCompiledBytes)
	}
	msgs, methods := d.Messages, d.Methods
	if len(methods) == 0 {
		return nil, errors.New("no method")
	}
	if len(methods) > MaxMethods {
		return nil, fmt.Errorf("%d methods, over %d", len(methods), MaxMethods)
	}
	if len(msgs) > MaxMessages {
		return nil, fmt.Errorf("%d messages, over %d", len(msgs), MaxMessages)
	}
	s := &Schema{
		id: d.ID, source: d.Source, size: d.Size,
		messages: make([]Message, len(msgs)),
		methods:  make(map[string]*Message, len(methods)),
		byName:   make(map[string]*Message, len(msgs)),
	}
	total := 0
	for i := range msgs {
		md := &msgs[i]
		if err := checkFullName(md.FullName); err != nil {
			return nil, fmt.Errorf("message %d: %w", i, err)
		}
		if _, dup := s.byName[md.FullName]; dup {
			return nil, fmt.Errorf("message %s twice", md.FullName)
		}
		if len(md.Fields) > MaxMessageFields {
			return nil, fmt.Errorf("message %s: %d fields, over %d", md.FullName, len(md.Fields), MaxMessageFields)
		}
		if total += len(md.Fields); total > MaxFields {
			return nil, fmt.Errorf("over %d fields", MaxFields)
		}
		m := &s.messages[i]
		m.FullName, m.Any = md.FullName, md.Any
		m.fields = make([]Field, len(md.Fields))
		s.byName[md.FullName] = m
	}
	for i := range msgs {
		m := &s.messages[i]
		for j := range msgs[i].Fields {
			f := &m.fields[j]
			if err := s.field(f, &msgs[i].Fields[j]); err != nil {
				return nil, fmt.Errorf("message %s field %d: %w", m.FullName, j, err)
			}
			if j > 0 && f.Number <= m.fields[j-1].Number {
				return nil, fmt.Errorf("message %s: fields not sorted by number, or number %d twice", m.FullName, f.Number)
			}
		}
		if m.Any {
			if f := m.Field(1); f == nil || f.Kind != KindString {
				return nil, fmt.Errorf("message %s: an Any without a string type_url (1)", m.FullName)
			}
			if f := m.Field(2); f == nil || f.Kind != KindBytes {
				return nil, fmt.Errorf("message %s: an Any without a bytes value (2)", m.FullName)
			}
		}
		if n := len(m.fields); n > 0 {
			if largest := int(m.fields[n-1].Number); largest < maxDenseMultiplier*n+8 {
				m.dense = make([]uint16, largest+1)
				for k := range m.fields {
					m.dense[m.fields[k].Number] = uint16(k + 1) // #nosec G115 -- at most MaxMessageFields
				}
			}
		}
	}
	prev := ""
	for i, md := range methods {
		if err := checkPath(md.Path); err != nil {
			return nil, fmt.Errorf("method %d: %w", i, err)
		}
		if i > 0 && md.Path <= prev {
			return nil, fmt.Errorf("methods not sorted, or %s twice", md.Path)
		}
		prev = md.Path
		if int64(md.Input) >= int64(len(msgs)) || int64(md.Output) >= int64(len(msgs)) {
			return nil, fmt.Errorf("method %s: a type out of range", md.Path)
		}
		s.methods[md.Path] = &s.messages[md.Input]
	}
	return s, nil
}

// field checks fd and converts it into f.
func (s *Schema) field(f *Field, fd *FieldDef) error {
	if fd.Number > uint32(protowire.MaxValidNumber) {
		return fmt.Errorf("number %d out of range", fd.Number)
	}
	num := protowire.Number(fd.Number) // #nosec G115 -- at most MaxValidNumber
	if !num.IsValid() {
		return fmt.Errorf("number %d out of range", fd.Number)
	}
	if err := checkFieldName(fd.Name); err != nil {
		return fmt.Errorf("number %d: %w", num, err)
	}
	f.Number, f.Name, f.Kind, f.Repeated = num, fd.Name, fd.Kind, fd.Repeated
	if f.Kind < KindString || f.Kind > KindFixed64 {
		return fmt.Errorf("%s: unknown kind %d", f.Name, fd.Kind)
	}
	if f.Kind == KindMessage || f.Kind == KindGroup {
		if int64(fd.Message) >= int64(len(s.messages)) {
			return fmt.Errorf("%s: type %d out of range", f.Name, fd.Message)
		}
		f.Message = &s.messages[fd.Message]
	} else if fd.Message != 0 {
		return fmt.Errorf("%s: a type for a field that isn't a message", f.Name)
	}
	return nil
}

// checkFieldName checks a field's name: a proto identifier, or an
// extension's full name in brackets.
func checkFieldName(name string) error {
	if inner, ok := strings.CutPrefix(name, "["); ok {
		inner, ok = strings.CutSuffix(inner, "]")
		if !ok || len(name) > maxExtensionName {
			return fmt.Errorf("extension name %.40q not [full.name] of at most %d bytes", name, MaxFullName)
		}
		return checkFullName(inner)
	}
	if len(name) > MaxFieldName {
		return fmt.Errorf("name %.40q over %d bytes", name, MaxFieldName)
	}
	if !identifier(name) {
		return fmt.Errorf("name %.40q not an identifier", name)
	}
	return nil
}

// checkFullName checks a full name: identifiers joined by dots.
func checkFullName(name string) error {
	if len(name) > MaxFullName {
		return fmt.Errorf("full name %.40q over %d bytes", name, MaxFullName)
	}
	for part := range strings.SplitSeq(name, ".") {
		if !identifier(part) {
			return fmt.Errorf("full name %.40q not identifiers joined by dots", name)
		}
	}
	return nil
}

// checkPath checks a method's path: "/" service full name "/" method.
func checkPath(path string) error {
	if len(path) > MaxFullName {
		return fmt.Errorf("path %.40q over %d bytes", path, MaxFullName)
	}
	service, method, ok := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if !strings.HasPrefix(path, "/") || !ok || checkFullName(service) != nil || !identifier(method) {
		return fmt.Errorf("path %.40q not /package.Service/Method", path)
	}
	return nil
}

// identifier reports whether s is a proto identifier: a letter or '_',
// then letters, digits and '_'.
func identifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_', 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
