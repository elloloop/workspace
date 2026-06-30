package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil error", err: nil, want: false},
		{name: "plain non-pg error", err: errors.New("boom"), want: false},
		{name: "unique violation 23505", err: &pgconn.PgError{Code: "23505"}, want: true},
		{name: "different pg code", err: &pgconn.PgError{Code: "23503"}, want: false},
		{name: "wrapped unique violation", err: errors.Join(errors.New("ctx"), &pgconn.PgError{Code: "23505"}), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isUniqueViolation(tt.err); got != tt.want {
				t.Fatalf("isUniqueViolation(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestProjectConfigRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   service.Project
	}{
		{
			name: "zero config",
			in:   service.Project{},
		},
		{
			name: "region and reads only",
			in:   service.Project{DataRegion: "eu-west-1", MaxCheckReads: 42},
		},
		{
			name: "with model",
			in:   service.Project{DataRegion: "us-east-1", MaxCheckReads: 7, Model: authz.DefaultModel()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			in := tt.in
			blob, err := encodeProjectConfig(&in)
			if err != nil {
				t.Fatalf("encodeProjectConfig: %v", err)
			}

			var got service.Project
			if err := decodeProjectConfig(blob, &got); err != nil {
				t.Fatalf("decodeProjectConfig: %v", err)
			}

			if got.DataRegion != in.DataRegion {
				t.Errorf("DataRegion = %q, want %q", got.DataRegion, in.DataRegion)
			}
			if got.MaxCheckReads != in.MaxCheckReads {
				t.Errorf("MaxCheckReads = %d, want %d", got.MaxCheckReads, in.MaxCheckReads)
			}

			// A nil input Model stays nil; a populated one round-trips to an
			// equivalent model (re-marshal both and compare the canonical bytes).
			if (in.Model == nil) != (got.Model == nil) {
				t.Fatalf("Model presence mismatch: in nil=%v, got nil=%v", in.Model == nil, got.Model == nil)
			}
			if in.Model != nil {
				want, err := authz.MarshalModel(in.Model)
				if err != nil {
					t.Fatalf("MarshalModel(in): %v", err)
				}
				have, err := authz.MarshalModel(got.Model)
				if err != nil {
					t.Fatalf("MarshalModel(got): %v", err)
				}
				if string(want) != string(have) {
					t.Errorf("Model round-trip mismatch:\n want %s\n  got %s", want, have)
				}
			}
		})
	}
}

func TestDecodeProjectConfigEmptyBlob(t *testing.T) {
	t.Parallel()

	// An empty blob (the NULL / unset config_json case) leaves the project's
	// fields untouched and returns no error.
	p := service.Project{DataRegion: "preset", MaxCheckReads: 3}
	if err := decodeProjectConfig("", &p); err != nil {
		t.Fatalf("decodeProjectConfig(\"\"): %v", err)
	}
	if p.DataRegion != "preset" || p.MaxCheckReads != 3 || p.Model != nil {
		t.Fatalf("empty blob mutated project: %+v", p)
	}
}

func TestDecodeProjectConfigMalformed(t *testing.T) {
	t.Parallel()

	var p service.Project
	if err := decodeProjectConfig("{not json", &p); err == nil {
		t.Fatal("decodeProjectConfig(malformed) = nil error, want error")
	}
}

func TestSeatLockKey(t *testing.T) {
	t.Parallel()

	// Deterministic: same inputs produce the same key.
	a := seatLockKey("proj1", "tenant1", "sku1")
	b := seatLockKey("proj1", "tenant1", "sku1")
	if a != b {
		t.Fatalf("seatLockKey not deterministic: %q != %q", a, b)
	}

	// Distinct inputs in any single position produce distinct keys, and the
	// 0x1F separator prevents field-boundary collisions (e.g. "a"|"bc" vs "ab"|"c").
	keys := map[string]string{
		"baseline":         seatLockKey("proj1", "tenant1", "sku1"),
		"diff project":     seatLockKey("proj2", "tenant1", "sku1"),
		"diff tenant":      seatLockKey("proj1", "tenant2", "sku1"),
		"diff sku":         seatLockKey("proj1", "tenant1", "sku2"),
		"boundary shift a": seatLockKey("a", "bc", "sku1"),
		"boundary shift b": seatLockKey("ab", "c", "sku1"),
	}

	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if prev, dup := seen[key]; dup {
			t.Errorf("key collision between %q and %q: %q", prev, name, key)
		}
		seen[key] = name
	}

	if want := "seat\x1fproj1\x1ftenant1\x1fsku1"; keys["baseline"] != want {
		t.Errorf("baseline key = %q, want %q", keys["baseline"], want)
	}
}
