package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/elloloop/workspace/internal/repo/memory"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// TestCreateProjectRejectsControlCharID pins the durable seam: a client-supplied
// project id carrying a control char (NUL or 0x01) is rejected with
// ErrInvalidArgument before it can reach storage and forge a scope key, for both
// CreateProject and UpdateProject — covering the AdminService path that does not
// pass through the connect handler's validateScopeIDs.
func TestCreateProjectRejectsControlCharID(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()

	for _, id := range []string{"p\x00x", "p\x01x", "\x1fp"} {
		if _, err := svc.CreateProject(ctx, id, "n", nil, "", 0); !errors.Is(err, service.ErrInvalidArgument) {
			t.Fatalf("CreateProject(%q) = %v, want ErrInvalidArgument", id, err)
		}
		if _, err := svc.UpdateProject(ctx, id, "n", "", nil, "", false, 0, false); !errors.Is(err, service.ErrInvalidArgument) {
			t.Fatalf("UpdateProject(%q) = %v, want ErrInvalidArgument", id, err)
		}
	}

	// A control-char-free id is accepted (no false positive on path-like ids).
	if _, err := svc.CreateProject(ctx, "tenant/sub-1", "n", nil, "", 0); err != nil {
		t.Fatalf("CreateProject(path-like id) = %v, want nil", err)
	}
}

// TestWriteTuplesRejectsControlCharFields pins that WriteTuples rejects a control
// char in ANY tuple string field (namespace, object_id, relation, subject
// user_id, and subject-set fields) with ErrInvalidArgument, so a control char
// can never reach a driver's key derivation.
func TestWriteTuplesRejectsControlCharFields(t *testing.T) {
	svc := service.New(memory.New(), nil, nil)
	ctx := context.Background()
	p := service.Principal{ProjectID: "p"}

	write := func(tp authz.Tuple) error {
		_, err := svc.WriteTuples(ctx, p, []service.TupleOp{{Tuple: tp}})
		return err
	}

	cases := []authz.Tuple{
		{Namespace: "doc\x00x", ObjectID: "o", Relation: "viewer", Subject: authz.Subject{UserID: "u"}},
		{Namespace: "doc", ObjectID: "o\x01x", Relation: "viewer", Subject: authz.Subject{UserID: "u"}},
		{Namespace: "doc", ObjectID: "o", Relation: "view\x1fr", Subject: authz.Subject{UserID: "u"}},
		{Namespace: "doc", ObjectID: "o", Relation: "viewer", Subject: authz.Subject{UserID: "u\x00"}},
		{Namespace: "doc", ObjectID: "o", Relation: "viewer", Subject: authz.Subject{Set: &authz.SubjectSet{Namespace: "group\x00", ObjectID: "g", Relation: "member"}}},
		{Namespace: "doc", ObjectID: "o", Relation: "viewer", Subject: authz.Subject{Set: &authz.SubjectSet{Namespace: "group", ObjectID: "g\x01", Relation: "member"}}},
		{Namespace: "doc", ObjectID: "o", Relation: "viewer", Subject: authz.Subject{Set: &authz.SubjectSet{Namespace: "group", ObjectID: "g", Relation: "memb\x02r"}}},
	}
	for i, c := range cases {
		if err := write(c); !errors.Is(err, service.ErrInvalidArgument) {
			t.Fatalf("case %d: WriteTuples(%+v) = %v, want ErrInvalidArgument", i, c, err)
		}
	}

	// A path-like object_id ('/' and '|') is legitimate and accepted.
	if err := write(authz.Tuple{Namespace: "doc", ObjectID: "folder/doc|v2", Relation: "viewer", Subject: authz.Subject{UserID: "u"}}); err != nil {
		t.Fatalf("WriteTuples(path-like object_id) = %v, want nil", err)
	}
}
