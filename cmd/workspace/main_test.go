package main

import "testing"

// TestParseMigrateArgs pins the flag-based migrate subcommand: expand by default,
// --contract / -contract selects contract, and an unknown/typo'd or extra arg
// errors (so it cannot silently fall through to expand).
func TestParseMigrateArgs(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantContract bool
		wantErr      bool
	}{
		{name: "no args is expand", args: nil},
		{name: "double dash contract", args: []string{"--contract"}, wantContract: true},
		{name: "single dash contract", args: []string{"-contract"}, wantContract: true},
		{name: "explicit false", args: []string{"--contract=false"}},
		{name: "typo errors", args: []string{"--contrct"}, wantErr: true},
		{name: "unknown flag errors", args: []string{"--expand"}, wantErr: true},
		{name: "positional arg errors", args: []string{"contract"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			contract, err := parseMigrateArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseMigrateArgs(%v): want error, got contract=%v", tc.args, contract)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseMigrateArgs(%v): unexpected error: %v", tc.args, err)
			}
			if contract != tc.wantContract {
				t.Fatalf("parseMigrateArgs(%v) contract=%v, want %v", tc.args, contract, tc.wantContract)
			}
		})
	}
}
