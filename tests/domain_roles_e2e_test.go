package tests

import (
	"context"
	"testing"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
)

// TestProductDefinedDomainRoles proves issue #17: a product configures its OWN
// domain role hierarchy (instructor ⊃ ta ⊃ learner) and a course→content
// inheritance through a per-project model — no new API, just the configurable
// model from #27 — and Check evaluates it correctly. It also proves the custom
// model is OVERLAID on the built-in surface and is isolated to its project.
func TestProductDefinedDomainRoles(t *testing.T) {
	h := newAdminHarness(t)
	ctx := context.Background()

	// A learning platform's roles: instructor ⊃ ta ⊃ learner, with permissions
	// computed off the role hierarchy, and content that inherits from its course.
	const model = `{
	  "course": {
	    "instructor": {"this": true},
	    "ta":         {"union": [{"this": true}, {"computed": "instructor"}]},
	    "learner":    {"union": [{"this": true}, {"computed": "ta"}]},
	    "can_manage": {"computed": "instructor"},
	    "can_grade":  {"computed": "ta"},
	    "can_view":   {"computed": "learner"}
	  },
	  "content": {
	    "parent": {"this": true},
	    "viewer": {"union": [{"this": true}, {"tupleToUserset": {"tupleset": "parent", "computed": "learner"}}]},
	    "editor": {"union": [{"this": true}, {"tupleToUserset": {"tupleset": "parent", "computed": "instructor"}}]}
	  }
	}`

	if _, err := h.admin.CreateProject(ctx, reqAdmin(&workspacev1.CreateProjectRequest{
		Id: "edu", Name: "Learning Platform", ModelJson: model,
	})); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}

	courseSet := &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
		Namespace: "course", ObjectId: "c1", Relation: "learner",
	}}}
	writes := []*workspacev1.TupleUpdate{
		ins("course", "c1", "instructor", subjUser("alice")), // instructor
		ins("course", "c1", "ta", subjUser("bob")),           // TA
		ins("course", "c1", "learner", subjUser("carol")),    // learner
		ins("content", "lesson1", "parent", courseSet),       // lesson1 belongs to course c1
	}
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{ProjectId: "edu", Updates: writes})); err != nil {
		t.Fatalf("WriteRelationTuples: %v", err)
	}

	check := func(ns, obj, rel, user string) bool {
		t.Helper()
		got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
			ProjectId: "edu", Namespace: ns, ObjectId: obj, Relation: rel, SubjectUserId: user,
		}))
		if err != nil {
			t.Fatalf("Check %s:%s#%s@%s: %v", ns, obj, rel, user, err)
		}
		return got.Msg.Allowed
	}

	// Role hierarchy: instructor ⊃ ta ⊃ learner, so permissions cascade down.
	type want struct{ manage, grade, view bool }
	for user, w := range map[string]want{
		"alice": {true, true, true},   // instructor: everything
		"bob":   {false, true, true},  // TA: grade + view, not manage
		"carol": {false, false, true}, // learner: view only
		"dan":   {false, false, false},
	} {
		if g := check("course", "c1", "can_manage", user); g != w.manage {
			t.Errorf("can_manage@%s = %v, want %v", user, g, w.manage)
		}
		if g := check("course", "c1", "can_grade", user); g != w.grade {
			t.Errorf("can_grade@%s = %v, want %v", user, g, w.grade)
		}
		if g := check("course", "c1", "can_view", user); g != w.view {
			t.Errorf("can_view@%s = %v, want %v", user, g, w.view)
		}
	}

	// Content inherits from its course: instructors edit, every role views.
	if !check("content", "lesson1", "editor", "alice") {
		t.Error("instructor alice should edit course content")
	}
	for _, u := range []string{"bob", "carol"} {
		if check("content", "lesson1", "editor", u) {
			t.Errorf("%s should not edit content (not an instructor)", u)
		}
		if !check("content", "lesson1", "viewer", u) {
			t.Errorf("%s (course member) should view content", u)
		}
	}
	if check("content", "lesson1", "viewer", "dan") {
		t.Error("dan (no course role) must not view content")
	}

	// The custom model is OVERLAID on the built-in surface: the workspace role
	// hierarchy still works in project "edu".
	if _, err := h.authz.WriteRelationTuples(ctx, req(&workspacev1.WriteRelationTuplesRequest{
		ProjectId: "edu", Updates: []*workspacev1.TupleUpdate{ins("workspace", "w1", "owner", subjUser("alice"))},
	})); err != nil {
		t.Fatalf("WriteRelationTuples workspace: %v", err)
	}
	if !check("workspace", "w1", "member", "alice") {
		t.Error("built-in workspace owner⊃member lost under a custom model")
	}

	// Isolation: the "course" namespace and these grants exist only in "edu".
	// In the default project, course:c1#can_view@alice is just an unknown
	// relation with no direct tuple → denied.
	got, err := h.authz.Check(ctx, req(&workspacev1.CheckRequest{
		Namespace: "course", ObjectId: "c1", Relation: "can_view", SubjectUserId: "alice",
	}))
	if err != nil {
		t.Fatalf("default-project Check: %v", err)
	}
	if got.Msg.Allowed {
		t.Error("project edu's custom roles leaked into the default project")
	}
}

func ins(ns, obj, rel string, subj *workspacev1.Subject) *workspacev1.TupleUpdate {
	return &workspacev1.TupleUpdate{
		Op:    workspacev1.TupleUpdate_OP_INSERT,
		Tuple: &workspacev1.RelationTuple{ProjectId: "edu", Namespace: ns, ObjectId: obj, Relation: rel, Subject: subj},
	}
}
