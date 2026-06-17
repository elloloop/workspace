package consistencytoken

import (
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	cases := []Token{
		{Project: "default", Tenant: "", Seq: 0},
		{Project: "proj", Tenant: "tenantA", Seq: 42},
		{Project: "p", Tenant: "t", Seq: 9223372036854775807},
	}
	for _, want := range cases {
		got, err := Decode(Encode(want.Project, want.Tenant, want.Seq))
		if err != nil {
			t.Fatalf("Decode(Encode(%+v)): %v", want, err)
		}
		if got != want {
			t.Fatalf("round trip = %+v, want %+v", got, want)
		}
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, s := range []string{
		"",
		"not-a-token",
		"ct1.@@@notbase64@@@",
		"ct1." + "eyJleHRyYSI6MX0", // base64 of {"extra":1} — unknown field
		"ct0.abc",                  // wrong version prefix
	} {
		if _, err := Decode(s); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Decode(%q) err = %v, want ErrMalformed", s, err)
		}
	}
}
