// Package consistencytoken encodes and decodes the opaque "zookie" a caller
// uses to assert read-after-write consistency.
//
// A token names a (project, tenant) shard and a monotonic write sequence. A
// WriteRelationTuples response returns the sequence reached by that write; a
// later read may carry the token to demand state at least that fresh. The token
// is opaque to clients but structurally parseable and validated by the server
// (so garbage is rejected, not silently honored). It asserts FRESHNESS, not
// authority — the caller is already authenticated — so it is intentionally NOT
// signed.
package consistencytoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// prefix versions the wire format so the encoding can evolve.
const prefix = "ct1."

// Token is the decoded form: the shard it was issued for and the monotonic
// write sequence the issuing write reached.
type Token struct {
	Project string `json:"p"`
	Tenant  string `json:"t"`
	Seq     int64  `json:"s"`
}

// ErrMalformed is returned when a token is not a well-formed consistency token.
var ErrMalformed = errors.New("malformed consistency token")

// Encode renders a token. Seq must be >= 0.
func Encode(project, tenant string, seq int64) string {
	b, _ := json.Marshal(Token{Project: project, Tenant: tenant, Seq: seq})
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// Decode parses a token, returning ErrMalformed for anything that is not a
// token this server issued in a recognized format.
func Decode(s string) (Token, error) {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return Token{}, fmt.Errorf("%w: bad prefix", ErrMalformed)
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return Token{}, fmt.Errorf("%w: bad base64", ErrMalformed)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var t Token
	if err := dec.Decode(&t); err != nil {
		return Token{}, fmt.Errorf("%w: bad payload", ErrMalformed)
	}
	if t.Seq < 0 {
		return Token{}, fmt.Errorf("%w: negative sequence", ErrMalformed)
	}
	return t, nil
}
