package jwt

import (
	"context"
	"testing"
	"time"
)

func TestHS256RoundTrip(t *testing.T) {
	const secret = "shhhhh-do-not-tell" //nolint:gosec // test-only signing secret
	tok, err := MintHS256(secret, "identity", "alice", "proj-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v := NewHS256Verifier(secret, "identity")
	claims, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims.UserID != "alice" || claims.ProjectID != "proj-1" || claims.Issuer != "identity" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestHS256RejectsWrongSecret(t *testing.T) {
	tok, _ := MintHS256("right", "identity", "alice", "", time.Hour)
	if _, err := NewHS256Verifier("wrong", "identity").Verify(context.Background(), tok); err == nil {
		t.Fatal("want error on wrong secret")
	}
}

func TestHS256RejectsWrongIssuer(t *testing.T) {
	tok, _ := MintHS256("s", "evil", "alice", "", time.Hour)
	if _, err := NewHS256Verifier("s", "identity").Verify(context.Background(), tok); err == nil {
		t.Fatal("want error on issuer mismatch")
	}
}

func TestHS256RejectsExpired(t *testing.T) {
	tok, _ := MintHS256("s", "identity", "alice", "", -time.Minute)
	if _, err := NewHS256Verifier("s", "identity").Verify(context.Background(), tok); err == nil {
		t.Fatal("want error on expired token")
	}
}
