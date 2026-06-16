package authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// A project's authorization model is configured out of band and persisted as
// JSON. ModelDoc is the serializable form of Model: a map of namespace →
// relation → rewrite. The JSON form of each rewrite is one of:
//
//	{"this": true}
//	{"computed": "<relation>"}
//	{"tupleToUserset": {"tupleset": "<rel>", "computed": "<rel>"}}
//	{"union": [<rewrite>, ...]}
//	{"intersection": [<rewrite>, ...]}
//	{"exclusion": {"include": <rewrite>, "exclude": <rewrite>}}
//
// Exactly one form must be set per rewrite. ParseModel round-trips with
// MarshalModel and rejects unknown fields and malformed rewrites.

// ModelDoc is the JSON document form of a Model.
type ModelDoc map[string]map[string]RewriteDoc

// RewriteDoc is the JSON form of a single Rewrite. Exactly one field is set.
type RewriteDoc struct {
	This           bool               `json:"this,omitempty"`
	Computed       string             `json:"computed,omitempty"`
	TupleToUserset *TupleToUsersetDoc `json:"tupleToUserset,omitempty"`
	Union          []RewriteDoc       `json:"union,omitempty"`
	Intersection   []RewriteDoc       `json:"intersection,omitempty"`
	Exclusion      *ExclusionDoc      `json:"exclusion,omitempty"`
}

// TupleToUsersetDoc is the JSON form of a tuple-to-userset rewrite.
type TupleToUsersetDoc struct {
	Tupleset string `json:"tupleset"`
	Computed string `json:"computed"`
}

// ExclusionDoc is the JSON form of an exclusion (difference) rewrite.
type ExclusionDoc struct {
	Include RewriteDoc `json:"include"`
	Exclude RewriteDoc `json:"exclude"`
}

// ParseModel decodes a JSON model document into a validated Model. It rejects
// unknown fields and any rewrite that does not set exactly one operator.
func ParseModel(data []byte) (Model, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc ModelDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("authz: decode model: %w", err)
	}
	return doc.ToModel()
}

// MarshalModel encodes a Model to its JSON document form.
func MarshalModel(m Model) ([]byte, error) {
	return json.Marshal(FromModel(m))
}

// ToModel converts a document to the in-memory Model, validating each rewrite.
func (d ModelDoc) ToModel() (Model, error) {
	m := make(Model, len(d))
	for ns, rels := range d {
		if ns == "" {
			return nil, errors.New("authz: model has an empty namespace name")
		}
		nm := make(Namespace, len(rels))
		for rel, rd := range rels {
			if rel == "" {
				return nil, fmt.Errorf("authz: namespace %q has an empty relation name", ns)
			}
			rw, err := rd.toRewrite()
			if err != nil {
				return nil, fmt.Errorf("authz: %s#%s: %w", ns, rel, err)
			}
			nm[rel] = rw
		}
		m[ns] = nm
	}
	return m, nil
}

func (rd RewriteDoc) toRewrite() (Rewrite, error) {
	set := 0
	if rd.This {
		set++
	}
	if rd.Computed != "" {
		set++
	}
	if rd.TupleToUserset != nil {
		set++
	}
	if rd.Union != nil {
		set++
	}
	if rd.Intersection != nil {
		set++
	}
	if rd.Exclusion != nil {
		set++
	}
	if set != 1 {
		return Rewrite{}, fmt.Errorf("rewrite must set exactly one operator, got %d", set)
	}

	switch {
	case rd.This:
		return this(), nil
	case rd.Computed != "":
		return computed(rd.Computed), nil
	case rd.TupleToUserset != nil:
		if rd.TupleToUserset.Tupleset == "" || rd.TupleToUserset.Computed == "" {
			return Rewrite{}, errors.New("tupleToUserset requires tupleset and computed")
		}
		return tupleToUserset(rd.TupleToUserset.Tupleset, rd.TupleToUserset.Computed), nil
	case rd.Union != nil:
		children, err := toRewrites(rd.Union)
		if err != nil {
			return Rewrite{}, err
		}
		if len(children) == 0 {
			return Rewrite{}, errors.New("union requires at least one child")
		}
		return union(children...), nil
	case rd.Intersection != nil:
		children, err := toRewrites(rd.Intersection)
		if err != nil {
			return Rewrite{}, err
		}
		if len(children) == 0 {
			return Rewrite{}, errors.New("intersection requires at least one child")
		}
		return intersection(children...), nil
	default: // rd.Exclusion != nil
		inc, err := rd.Exclusion.Include.toRewrite()
		if err != nil {
			return Rewrite{}, fmt.Errorf("exclusion.include: %w", err)
		}
		exc, err := rd.Exclusion.Exclude.toRewrite()
		if err != nil {
			return Rewrite{}, fmt.Errorf("exclusion.exclude: %w", err)
		}
		return exclusion(inc, exc), nil
	}
}

func toRewrites(docs []RewriteDoc) ([]Rewrite, error) {
	out := make([]Rewrite, 0, len(docs))
	for i, d := range docs {
		rw, err := d.toRewrite()
		if err != nil {
			return nil, fmt.Errorf("child %d: %w", i, err)
		}
		out = append(out, rw)
	}
	return out, nil
}

// FromModel converts an in-memory Model to its document form.
func FromModel(m Model) ModelDoc {
	doc := make(ModelDoc, len(m))
	for ns, rels := range m {
		nd := make(map[string]RewriteDoc, len(rels))
		for rel, rw := range rels {
			nd[rel] = fromRewrite(rw)
		}
		doc[ns] = nd
	}
	return doc
}

func fromRewrite(rw Rewrite) RewriteDoc {
	switch {
	case len(rw.Union) > 0:
		return RewriteDoc{Union: fromRewrites(rw.Union)}
	case len(rw.Intersection) > 0:
		return RewriteDoc{Intersection: fromRewrites(rw.Intersection)}
	case rw.Exclusion != nil:
		return RewriteDoc{Exclusion: &ExclusionDoc{
			Include: fromRewrite(rw.Exclusion.Include),
			Exclude: fromRewrite(rw.Exclusion.Exclude),
		}}
	case rw.Computed != "":
		return RewriteDoc{Computed: rw.Computed}
	case rw.TuplesetRelation != "":
		return RewriteDoc{TupleToUserset: &TupleToUsersetDoc{
			Tupleset: rw.TuplesetRelation,
			Computed: rw.ComputedRelation,
		}}
	default:
		return RewriteDoc{This: true}
	}
}

func fromRewrites(rws []Rewrite) []RewriteDoc {
	out := make([]RewriteDoc, 0, len(rws))
	for _, rw := range rws {
		out = append(out, fromRewrite(rw))
	}
	return out
}
