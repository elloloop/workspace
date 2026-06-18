package connect

import (
	"testing"

	"connectrpc.com/connect"
)

func TestValidateScopeIDs(t *testing.T) {
	cases := []struct {
		name    string
		ids     []string
		wantErr bool
	}{
		{"normal ids", []string{"proj-1", "tenant_a"}, false},
		{"empty ids ok", []string{"", ""}, false},
		{"unicode ok", []string{"projé", "租户"}, false},
		{"nul in first", []string{"a\x00b", "t"}, true},
		{"nul in second", []string{"p", "a\x00b"}, true},
		{"low control char", []string{"a\x01b"}, true},
		{"tab is a control char", []string{"a\tb"}, true},
		{"del is allowed (0x7f, not <0x20)", []string{"a\x7fb"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateScopeIDs(c.ids...)
			if c.wantErr {
				if err == nil {
					t.Fatalf("validateScopeIDs(%q) = nil, want error", c.ids)
				}
				if connect.CodeOf(err) != connect.CodeInvalidArgument {
					t.Fatalf("validateScopeIDs(%q) code = %v, want InvalidArgument", c.ids, connect.CodeOf(err))
				}
			} else if err != nil {
				t.Fatalf("validateScopeIDs(%q) = %v, want nil", c.ids, err)
			}
		})
	}
}
