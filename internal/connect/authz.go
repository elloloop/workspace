package connect

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// structMap converts an optional proto Struct to a Go map (nil-safe).
func structMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

func subjectFromProto(s *workspacev1.Subject) (authz.Subject, error) {
	if s == nil {
		return authz.Subject{}, connect.NewError(connect.CodeInvalidArgument, errors.New("subject is required"))
	}
	switch k := s.Kind.(type) {
	case *workspacev1.Subject_UserId:
		return authz.Subject{UserID: k.UserId}, nil
	case *workspacev1.Subject_Set:
		if k.Set == nil {
			return authz.Subject{}, connect.NewError(connect.CodeInvalidArgument, errors.New("subject set is nil"))
		}
		return authz.Subject{Set: &authz.SubjectSet{
			Namespace: k.Set.Namespace, ObjectID: k.Set.ObjectId, Relation: k.Set.Relation,
		}}, nil
	case *workspacev1.Subject_Wildcard:
		if !k.Wildcard {
			return authz.Subject{}, connect.NewError(connect.CodeInvalidArgument, errors.New("wildcard subject must be true"))
		}
		return authz.Subject{Wildcard: true}, nil
	default:
		return authz.Subject{}, connect.NewError(connect.CodeInvalidArgument, errors.New("subject must set user_id, set, or wildcard"))
	}
}

func subjectToProto(s authz.Subject) *workspacev1.Subject {
	switch {
	case s.Wildcard:
		return &workspacev1.Subject{Kind: &workspacev1.Subject_Wildcard{Wildcard: true}}
	case s.Set != nil:
		return &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
			Namespace: s.Set.Namespace, ObjectId: s.Set.ObjectID, Relation: s.Set.Relation,
		}}}
	default:
		return &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: s.UserID}}
	}
}

func tupleFromProto(t *workspacev1.RelationTuple) (authz.Tuple, error) {
	if t == nil {
		return authz.Tuple{}, connect.NewError(connect.CodeInvalidArgument, errors.New("tuple is required"))
	}
	subj, err := subjectFromProto(t.Subject)
	if err != nil {
		return authz.Tuple{}, err
	}
	if t.ConditionName != "" {
		subj.Condition = &authz.Condition{Name: t.ConditionName, Params: structMap(t.ConditionParams)}
	}
	return authz.Tuple{
		Namespace: t.Namespace, ObjectID: t.ObjectId, Relation: t.Relation,
		Subject: subj, ExpiresAt: optTime(t.ExpiresAt),
	}, nil
}

func tupleToProto(projectID, tenantID string, t authz.Tuple) *workspacev1.RelationTuple {
	rt := &workspacev1.RelationTuple{
		ProjectId: projectID,
		TenantId:  tenantID,
		Namespace: t.Namespace,
		ObjectId:  t.ObjectID,
		Relation:  t.Relation,
		Subject:   subjectToProto(t.Subject),
		ExpiresAt: optTimestamp(t.ExpiresAt),
	}
	if c := t.Subject.Condition; c != nil && c.Name != "" {
		rt.ConditionName = c.Name
		if len(c.Params) > 0 {
			// Params originated from a proto Struct (JSON-safe), so this does
			// not fail in practice; on any error leave params unset.
			if s, err := structpb.NewStruct(c.Params); err == nil {
				rt.ConditionParams = s
			}
		}
	}
	return rt
}

// optTime converts an optional proto timestamp to *time.Time (nil = unset).
func optTime(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

// optTimestamp converts an optional *time.Time to a proto timestamp.
func optTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) WriteRelationTuples(ctx context.Context, req *connect.Request[workspacev1.WriteRelationTuplesRequest]) (*connect.Response[workspacev1.WriteRelationTuplesResponse], error) {
	if err := h.requireTenantRate(ctx, req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, err
	}
	p, err := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	ops := make([]service.TupleOp, 0, len(req.Msg.Updates))
	for _, u := range req.Msg.Updates {
		t, err := tupleFromProto(u.Tuple)
		if err != nil {
			return nil, err
		}
		switch u.Op {
		case workspacev1.TupleUpdate_OP_INSERT:
			ops = append(ops, service.TupleOp{Tuple: t})
		case workspacev1.TupleUpdate_OP_DELETE:
			ops = append(ops, service.TupleOp{Delete: true, Tuple: t})
		default:
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("update op must be INSERT or DELETE"))
		}
	}
	token, err := h.svc.WriteTuples(ctx, p, ops)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.WriteRelationTuplesResponse{ConsistencyToken: token}), nil
}

func (h *Handler) ReadRelationTuples(ctx context.Context, req *connect.Request[workspacev1.ReadRelationTuplesRequest]) (*connect.Response[workspacev1.ReadRelationTuplesResponse], error) {
	p, err := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.EnsureConsistency(ctx, p, req.Msg.AtLeastConsistencyToken); err != nil {
		return nil, errToConnect(err)
	}
	tuples, err := h.svc.ReadTuples(ctx, p, service.TupleFilter{
		Namespace:     req.Msg.Namespace,
		ObjectID:      req.Msg.ObjectId,
		Relation:      req.Msg.Relation,
		SubjectUserID: req.Msg.SubjectUserId,
	})
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.RelationTuple, 0, len(tuples))
	for _, t := range tuples {
		out = append(out, tupleToProto(p.ProjectID, p.TenantID, t))
	}
	return connect.NewResponse(&workspacev1.ReadRelationTuplesResponse{Tuples: out}), nil
}

func (h *Handler) Check(ctx context.Context, req *connect.Request[workspacev1.CheckRequest]) (*connect.Response[workspacev1.CheckResponse], error) {
	start := time.Now()
	defer func() { h.metrics.observe("Check", start) }()
	if err := h.requireTenantRate(ctx, req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, err
	}

	p, err := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.EnsureConsistency(ctx, p, req.Msg.AtLeastConsistencyToken); err != nil {
		h.metrics.recordError("Check")
		return nil, errToConnect(err)
	}
	userID, set := req.Msg.SubjectUserId, req.Msg.SubjectSet
	if (userID == "") == (set == nil) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("exactly one of subject_user_id or subject_set is required"))
	}

	ctx, backstops := authz.WithBackstops(ctx)
	defer func() { h.metrics.recordBackstops(backstops) }()

	var allowed bool
	if set != nil {
		allowed, err = h.svc.CheckSet(ctx, p, req.Msg.Namespace, req.Msg.ObjectId, req.Msg.Relation,
			authz.SubjectSet{Namespace: set.Namespace, ObjectID: set.ObjectId, Relation: set.Relation},
			structMap(req.Msg.Context))
	} else {
		allowed, err = h.svc.Check(ctx, p, req.Msg.Namespace, req.Msg.ObjectId, req.Msg.Relation, userID, structMap(req.Msg.Context))
	}
	if err != nil {
		h.metrics.recordError("Check")
		return nil, errToConnect(err)
	}
	h.metrics.recordDecision(req.Msg.Namespace, req.Msg.Relation, allowed)
	return connect.NewResponse(&workspacev1.CheckResponse{Allowed: allowed}), nil
}

func (h *Handler) Expand(ctx context.Context, req *connect.Request[workspacev1.ExpandRequest]) (*connect.Response[workspacev1.ExpandResponse], error) {
	start := time.Now()
	defer func() { h.metrics.observe("Expand", start) }()
	if err := h.requireTenantRate(ctx, req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, err
	}

	p, err := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.EnsureConsistency(ctx, p, req.Msg.AtLeastConsistencyToken); err != nil {
		h.metrics.recordError("Expand")
		return nil, errToConnect(err)
	}
	ctx, backstops := authz.WithBackstops(ctx)
	defer func() { h.metrics.recordBackstops(backstops) }()
	tree, err := h.svc.Expand(ctx, p, req.Msg.Namespace, req.Msg.ObjectId, req.Msg.Relation)
	if err != nil {
		h.metrics.recordError("Expand")
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.ExpandResponse{Tree: treeToProto(tree)}), nil
}

func treeToProto(t authz.Tree) *workspacev1.UsersetTree {
	node := &workspacev1.UsersetTree{
		Expanded: &workspacev1.SubjectSet{
			Namespace: t.Expanded.Namespace, ObjectId: t.Expanded.ObjectID, Relation: t.Expanded.Relation,
		},
	}
	switch {
	case len(t.Union) > 0:
		node.Type = workspacev1.UsersetTree_NODE_TYPE_UNION
		for _, c := range t.Union {
			node.Children = append(node.Children, treeToProto(c))
		}
	case len(t.Intersection) > 0:
		node.Type = workspacev1.UsersetTree_NODE_TYPE_INTERSECTION
		for _, c := range t.Intersection {
			node.Children = append(node.Children, treeToProto(c))
		}
	case t.Exclude != nil:
		// EXCLUSION encodes its operands explicitly: include minus exclude.
		// children stays empty.
		node.Type = workspacev1.UsersetTree_NODE_TYPE_EXCLUSION
		node.Include = treeToProto(t.Exclude.Include)
		node.Exclude = treeToProto(t.Exclude.Exclude)
	default:
		node.Type = workspacev1.UsersetTree_NODE_TYPE_LEAF
		node.UserIds = append(node.UserIds, t.Users...)
		node.Wildcard = t.Wildcard
		for _, set := range t.Sets {
			node.Sets = append(node.Sets, &workspacev1.SubjectSet{
				Namespace: set.Namespace, ObjectId: set.ObjectID, Relation: set.Relation,
			})
		}
	}
	return node
}

func (h *Handler) ListObjects(ctx context.Context, req *connect.Request[workspacev1.ListObjectsRequest]) (*connect.Response[workspacev1.ListObjectsResponse], error) {
	start := time.Now()
	defer func() { h.metrics.observe("ListObjects", start) }()
	if err := h.requireTenantRate(ctx, req.Msg.ProjectId, req.Msg.TenantId); err != nil {
		return nil, err
	}

	p, err := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := h.svc.EnsureConsistency(ctx, p, req.Msg.AtLeastConsistencyToken); err != nil {
		h.metrics.recordError("ListObjects")
		return nil, errToConnect(err)
	}
	ctx, backstops := authz.WithBackstops(ctx)
	defer func() { h.metrics.recordBackstops(backstops) }()
	ids, err := h.svc.ListObjects(ctx, p, req.Msg.Namespace, req.Msg.Relation, req.Msg.SubjectUserId)
	if err != nil {
		h.metrics.recordError("ListObjects")
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.ListObjectsResponse{ObjectIds: ids}), nil
}

func (h *Handler) DeprovisionUser(ctx context.Context, req *connect.Request[workspacev1.DeprovisionUserRequest]) (*connect.Response[workspacev1.DeprovisionUserResponse], error) {
	// Project-wide erase: throttle on the project's own RPC bucket (it ignores
	// tenant_id, so a per-tenant key would let tenant_id rotation evade it, and
	// its own keyspace keeps an erase storm from starving the Check hot path).
	if err := h.requireRPCRate(ctx, req.Msg.ProjectId, "deprovision"); err != nil {
		return nil, err
	}
	p, err := h.scope(ctx, req.Msg.ProjectId, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	n, err := h.svc.DeprovisionUser(ctx, p, req.Msg.UserId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.DeprovisionUserResponse{DeletedCount: int64(n)}), nil
}

func (h *Handler) ExportSubjectGrants(ctx context.Context, req *connect.Request[workspacev1.ExportSubjectGrantsRequest]) (*connect.Response[workspacev1.ExportSubjectGrantsResponse], error) {
	// Project-wide export gets its OWN rate bucket so an export storm cannot
	// starve the per-tenant Check hot path.
	if err := h.requireRPCRate(ctx, req.Msg.ProjectId, "export"); err != nil {
		return nil, err
	}
	// Route through scope so the data-residency guard runs at the same chokepoint
	// as every other RPC (and a residency refusal increments the refused metric);
	// the export is project-wide and ignores the tenant.
	p, err := h.scope(ctx, req.Msg.ProjectId, "")
	if err != nil {
		return nil, err
	}
	grants, err := h.svc.ExportSubjectGrants(ctx, p, req.Msg.UserId)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.SubjectGrant, 0, len(grants))
	for _, g := range grants {
		out = append(out, &workspacev1.SubjectGrant{
			TenantId:  g.TenantID,
			Namespace: g.Namespace,
			ObjectId:  g.ObjectID,
			Relation:  g.Relation,
			ViaGroup:  g.ViaGroup,
		})
	}
	return connect.NewResponse(&workspacev1.ExportSubjectGrantsResponse{Grants: out}), nil
}
