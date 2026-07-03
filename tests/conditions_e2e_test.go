package tests

import (
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

// mustStruct builds a structpb.Struct from a Go map for request context/params,
// failing the test on an invalid value. Shared by the condition-gated scenarios
// and the scoped-delegation suite.
func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	return s
}
