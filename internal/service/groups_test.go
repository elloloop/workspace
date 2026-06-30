package service

import "testing"

// TestMemberKeyRoundTrip pins MemberKey/MemberFromKey as exact inverses. The
// postgres enrollment-scan path (store.go) reconstructs a GroupMember from the
// stored (kind, id) pair, so a drift between the two would silently mislabel a
// user member as a group member (or vice versa) on read-back.
func TestMemberKeyRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   GroupMember
	}{
		{"user member", GroupMember{UserID: "alice"}},
		{"group member", GroupMember{GroupID: "eng"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, id := MemberKey(c.in)
			got := MemberFromKey(kind, id)
			if got != c.in {
				t.Fatalf("round-trip via (%q,%q) = %+v, want %+v", kind, id, got, c.in)
			}
		})
	}
}

// TestMemberFromKeyDefaultsToUser pins the fallback: any kind that is not
// "group" reconstructs a user member, mirroring MemberKey's "user" default.
func TestMemberFromKeyDefaultsToUser(t *testing.T) {
	if got := MemberFromKey("user", "bob"); got != (GroupMember{UserID: "bob"}) {
		t.Fatalf("user kind = %+v", got)
	}
	if got := MemberFromKey("", "bob"); got != (GroupMember{UserID: "bob"}) {
		t.Fatalf("empty kind must default to user, got %+v", got)
	}
}
