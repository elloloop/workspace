package authz

import (
	"strings"
	"testing"
)

func TestValidateModelRefs(t *testing.T) {
	// The built-in model references only declared relations.
	if err := ValidateModelRefs(DefaultModel()); err != nil {
		t.Fatalf("DefaultModel has dangling refs: %v", err)
	}

	good := Model{"course": {
		"enrolled": this(),
		"paid":     this(),
		"can_view": intersection(computed("enrolled"), computed("paid")),
	}}
	if err := ValidateModelRefs(good); err != nil {
		t.Fatalf("valid model rejected: %v", err)
	}

	cases := map[string]Model{
		"dangling computed": {"course": {
			"can_view": intersection(computed("enrolled"), computed("paid")), // neither declared
		}},
		"dangling in exclusion": {"course": {
			"member": this(),
			"view":   exclusion(computed("member"), computed("blocked")), // blocked undeclared
		}},
		"dangling tupleset": {"resource": {
			"viewer": tupleToUserset("parent", "member"), // parent undeclared
		}},
	}
	for name, m := range cases {
		if err := ValidateModelRefs(m); err == nil {
			t.Errorf("%s: expected a dangling-reference error, got nil", name)
		} else if !strings.Contains(err.Error(), "undeclared") {
			t.Errorf("%s: error %q should name the undeclared reference", name, err)
		}
	}
}
