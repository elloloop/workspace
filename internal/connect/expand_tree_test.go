package connect

import (
	"testing"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/pkg/authz"
)

// TestTreeToProtoExclusionExplicit pins that an exclusion Tree is converted to a
// proto node that encodes its operands EXPLICITLY in include/exclude, never by
// child position, while union/intersection still use children.
func TestTreeToProtoExclusionExplicit(t *testing.T) {
	incSet := authz.SubjectSet{Namespace: "doc", ObjectID: "d1", Relation: "member"}
	excSet := authz.SubjectSet{Namespace: "doc", ObjectID: "d1", Relation: "suspended"}
	tree := authz.Tree{
		Expanded: authz.SubjectSet{Namespace: "doc", ObjectID: "d1", Relation: "active_member"},
		Exclude: &authz.ExcludeTree{
			Include: authz.Tree{Expanded: incSet, Users: []string{"u1"}},
			Exclude: authz.Tree{Expanded: excSet, Users: []string{"u2"}},
		},
	}

	got := treeToProto(tree)

	if got.Type != workspacev1.UsersetTree_NODE_TYPE_EXCLUSION {
		t.Fatalf("type = %v, want EXCLUSION", got.Type)
	}
	if len(got.Children) != 0 {
		t.Fatalf("children = %d, want 0 for EXCLUSION", len(got.Children))
	}
	if got.Include == nil || got.Exclude == nil {
		t.Fatalf("include/exclude must be set, got include=%v exclude=%v", got.Include, got.Exclude)
	}
	if got.Include.Expanded.GetRelation() != "member" {
		t.Fatalf("include relation = %q, want member", got.Include.Expanded.GetRelation())
	}
	if got.Exclude.Expanded.GetRelation() != "suspended" {
		t.Fatalf("exclude relation = %q, want suspended", got.Exclude.Expanded.GetRelation())
	}
	if len(got.Include.UserIds) != 1 || got.Include.UserIds[0] != "u1" {
		t.Fatalf("include users = %v, want [u1]", got.Include.UserIds)
	}
	if len(got.Exclude.UserIds) != 1 || got.Exclude.UserIds[0] != "u2" {
		t.Fatalf("exclude users = %v, want [u2]", got.Exclude.UserIds)
	}
}

// TestTreeToProtoUnionUsesChildren confirms non-exclusion nodes keep using
// children and leave include/exclude unset.
func TestTreeToProtoUnionUsesChildren(t *testing.T) {
	self := authz.SubjectSet{Namespace: "doc", ObjectID: "d1", Relation: "viewer"}
	tree := authz.Tree{
		Expanded: self,
		Union: []authz.Tree{
			{Expanded: self, Users: []string{"a"}},
			{Expanded: self, Users: []string{"b"}},
		},
	}

	got := treeToProto(tree)

	if got.Type != workspacev1.UsersetTree_NODE_TYPE_UNION {
		t.Fatalf("type = %v, want UNION", got.Type)
	}
	if len(got.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(got.Children))
	}
	if got.Include != nil || got.Exclude != nil {
		t.Fatalf("include/exclude must be unset for UNION, got include=%v exclude=%v", got.Include, got.Exclude)
	}
}
