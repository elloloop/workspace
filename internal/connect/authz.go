package connect

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	workspacev1 "github.com/elloloop/workspaces/gen/go/workspace"
	"github.com/elloloop/workspaces/internal/service"
	"github.com/elloloop/workspaces/pkg/authz"
)

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
	default:
		return authz.Subject{}, connect.NewError(connect.CodeInvalidArgument, errors.New("subject must set user_id or set"))
	}
}

func subjectToProto(s authz.Subject) *workspacev1.Subject {
	if s.Set != nil {
		return &workspacev1.Subject{Kind: &workspacev1.Subject_Set{Set: &workspacev1.SubjectSet{
			Namespace: s.Set.Namespace, ObjectId: s.Set.ObjectID, Relation: s.Set.Relation,
		}}}
	}
	return &workspacev1.Subject{Kind: &workspacev1.Subject_UserId{UserId: s.UserID}}
}

func tupleFromProto(t *workspacev1.RelationTuple) (authz.Tuple, error) {
	if t == nil {
		return authz.Tuple{}, connect.NewError(connect.CodeInvalidArgument, errors.New("tuple is required"))
	}
	subj, err := subjectFromProto(t.Subject)
	if err != nil {
		return authz.Tuple{}, err
	}
	return authz.Tuple{Namespace: t.Namespace, ObjectID: t.ObjectId, Relation: t.Relation, Subject: subj}, nil
}

func tupleToProto(projectID string, t authz.Tuple) *workspacev1.RelationTuple {
	return &workspacev1.RelationTuple{
		ProjectId: projectID,
		Namespace: t.Namespace,
		ObjectId:  t.ObjectID,
		Relation:  t.Relation,
		Subject:   subjectToProto(t.Subject),
	}
}

func (h *Handler) WriteRelationTuples(ctx context.Context, req *connect.Request[workspacev1.WriteRelationTuplesRequest]) (*connect.Response[workspacev1.WriteRelationTuplesResponse], error) {
	p, err := principal(ctx)
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
	if err := h.svc.WriteTuples(ctx, p, ops); err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.WriteRelationTuplesResponse{}), nil
}

func (h *Handler) ReadRelationTuples(ctx context.Context, req *connect.Request[workspacev1.ReadRelationTuplesRequest]) (*connect.Response[workspacev1.ReadRelationTuplesResponse], error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
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
		out = append(out, tupleToProto(p.ProjectID, t))
	}
	return connect.NewResponse(&workspacev1.ReadRelationTuplesResponse{Tuples: out}), nil
}

func (h *Handler) Check(ctx context.Context, req *connect.Request[workspacev1.CheckRequest]) (*connect.Response[workspacev1.CheckResponse], error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	allowed, err := h.svc.Check(ctx, p, req.Msg.Namespace, req.Msg.ObjectId, req.Msg.Relation, req.Msg.SubjectUserId)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.CheckResponse{Allowed: allowed}), nil
}

func (h *Handler) Expand(ctx context.Context, req *connect.Request[workspacev1.ExpandRequest]) (*connect.Response[workspacev1.ExpandResponse], error) {
	p, err := principal(ctx)
	if err != nil {
		return nil, err
	}
	tree, err := h.svc.Expand(ctx, p, req.Msg.Namespace, req.Msg.ObjectId, req.Msg.Relation)
	if err != nil {
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
	if len(t.Union) > 0 {
		node.Type = workspacev1.UsersetTree_NODE_TYPE_UNION
		for _, c := range t.Union {
			node.Children = append(node.Children, treeToProto(c))
		}
		return node
	}
	node.Type = workspacev1.UsersetTree_NODE_TYPE_LEAF
	node.UserIds = append(node.UserIds, t.Users...)
	for _, set := range t.Sets {
		node.Sets = append(node.Sets, &workspacev1.SubjectSet{
			Namespace: set.Namespace, ObjectId: set.ObjectID, Relation: set.Relation,
		})
	}
	return node
}
