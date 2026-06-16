package authz

import (
	"reflect"
	"testing"
)

func TestModelJSONRoundTrip(t *testing.T) {
	models := map[string]Model{
		"default": DefaultModel(),
		"all-operators": {
			"course": {
				"enrolled":  this(),
				"paid":      this(),
				"suspended": this(),
				"can_view": exclusion(
					intersection(computed("enrolled"), computed("paid")),
					computed("suspended"),
				),
				"viewer": union(this(), tupleToUserset("parent", "member")),
			},
		},
	}
	for name, m := range models {
		t.Run(name, func(t *testing.T) {
			data, err := MarshalModel(m)
			if err != nil {
				t.Fatalf("MarshalModel: %v", err)
			}
			got, err := ParseModel(data)
			if err != nil {
				t.Fatalf("ParseModel: %v", err)
			}
			if !reflect.DeepEqual(got, m) {
				t.Fatalf("round-trip mismatch:\n got %#v\nwant %#v", got, m)
			}
		})
	}
}

func TestParseModelRejectsBadDocs(t *testing.T) {
	cases := map[string]string{
		"unknown field":      `{"ns":{"rel":{"bogus":true}}}`,
		"no operator":        `{"ns":{"rel":{}}}`,
		"two operators":      `{"ns":{"rel":{"this":true,"computed":"x"}}}`,
		"empty union":        `{"ns":{"rel":{"union":[]}}}`,
		"bad tupleToUserset": `{"ns":{"rel":{"tupleToUserset":{"tupleset":"x"}}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseModel([]byte(doc)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestParseModelExclusion(t *testing.T) {
	doc := `{"workspace":{"active":{"exclusion":{"include":{"computed":"member"},"exclude":{"computed":"suspended"}}}}}`
	m, err := ParseModel([]byte(doc))
	if err != nil {
		t.Fatalf("ParseModel: %v", err)
	}
	rw := m["workspace"]["active"]
	if rw.Exclusion == nil {
		t.Fatal("expected an exclusion rewrite")
	}
	if rw.Exclusion.Include.Computed != "member" || rw.Exclusion.Exclude.Computed != "suspended" {
		t.Fatalf("exclusion parsed wrong: %+v", rw.Exclusion)
	}
}
