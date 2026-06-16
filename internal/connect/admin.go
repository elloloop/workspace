package connect

import (
	"context"
	"crypto/subtle"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	workspacev1 "github.com/elloloop/workspace/gen/go/workspace/v1"
	"github.com/elloloop/workspace/internal/service"
	"github.com/elloloop/workspace/pkg/authz"
)

// adminSecretHeader is the platform-operator credential for the AdminService.
const adminSecretHeader = "X-Admin-Secret"

// requireAdmin gates the AdminService. When no admin secret is configured the
// service is disabled (CodeUnimplemented); otherwise the request must present
// the matching secret in the X-Admin-Secret header (constant-time compared).
func (h *Handler) requireAdmin(req connect.AnyRequest) error {
	if h.adminSecret == "" {
		return connect.NewError(connect.CodeUnimplemented, errors.New("admin API is disabled (no admin secret configured)"))
	}
	got := req.Header().Get(adminSecretHeader)
	if subtle.ConstantTimeCompare([]byte(got), []byte(h.adminSecret)) != 1 {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or missing admin secret"))
	}
	return nil
}

func projectStatusToProto(s service.ProjectStatus) workspacev1.ProjectStatus {
	switch s {
	case service.ProjectActive:
		return workspacev1.ProjectStatus_PROJECT_STATUS_ACTIVE
	case service.ProjectSuspended:
		return workspacev1.ProjectStatus_PROJECT_STATUS_SUSPENDED
	default:
		return workspacev1.ProjectStatus_PROJECT_STATUS_UNSPECIFIED
	}
}

func projectStatusFromProto(s workspacev1.ProjectStatus) service.ProjectStatus {
	switch s {
	case workspacev1.ProjectStatus_PROJECT_STATUS_ACTIVE:
		return service.ProjectActive
	case workspacev1.ProjectStatus_PROJECT_STATUS_SUSPENDED:
		return service.ProjectSuspended
	default:
		return "" // unspecified — UpdateProject leaves the status unchanged
	}
}

func projectToProto(p *service.Project) (*workspacev1.Project, error) {
	modelJSON := ""
	if len(p.Model) > 0 {
		raw, err := authz.MarshalModel(p.Model)
		if err != nil {
			return nil, err
		}
		modelJSON = string(raw)
	}
	return &workspacev1.Project{
		Id:        p.ID,
		Name:      p.Name,
		Status:    projectStatusToProto(p.Status),
		ModelJson: modelJSON,
		CreatedAt: timestamppb.New(p.CreatedAt),
		UpdatedAt: timestamppb.New(p.UpdatedAt),
	}, nil
}

// modelFromJSON parses the JSON model document. An empty string means the
// project uses the built-in default model (nil).
func modelFromJSON(s string) (authz.Model, error) {
	if s == "" {
		//nolint:nilnil // an empty model document legitimately means "use the built-in DefaultModel"; the resolver treats a nil model as the default.
		return nil, nil
	}
	m, err := authz.ParseModel([]byte(s))
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return m, nil
}

func (h *Handler) CreateProject(ctx context.Context, req *connect.Request[workspacev1.CreateProjectRequest]) (*connect.Response[workspacev1.CreateProjectResponse], error) {
	if err := h.requireAdmin(req); err != nil {
		return nil, err
	}
	model, err := modelFromJSON(req.Msg.ModelJson)
	if err != nil {
		return nil, err
	}
	p, err := h.svc.CreateProject(ctx, req.Msg.Id, req.Msg.Name, model)
	if err != nil {
		return nil, errToConnect(err)
	}
	pb, err := projectToProto(p)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.CreateProjectResponse{Project: pb}), nil
}

func (h *Handler) GetProject(ctx context.Context, req *connect.Request[workspacev1.GetProjectRequest]) (*connect.Response[workspacev1.GetProjectResponse], error) {
	if err := h.requireAdmin(req); err != nil {
		return nil, err
	}
	p, err := h.svc.GetProject(ctx, req.Msg.Id)
	if err != nil {
		return nil, errToConnect(err)
	}
	pb, err := projectToProto(p)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.GetProjectResponse{Project: pb}), nil
}

func (h *Handler) UpdateProject(ctx context.Context, req *connect.Request[workspacev1.UpdateProjectRequest]) (*connect.Response[workspacev1.UpdateProjectResponse], error) {
	if err := h.requireAdmin(req); err != nil {
		return nil, err
	}
	model, err := modelFromJSON(req.Msg.ModelJson)
	if err != nil {
		return nil, err
	}
	p, err := h.svc.UpdateProject(ctx, req.Msg.Id, req.Msg.Name, projectStatusFromProto(req.Msg.Status), model)
	if err != nil {
		return nil, errToConnect(err)
	}
	pb, err := projectToProto(p)
	if err != nil {
		return nil, errToConnect(err)
	}
	return connect.NewResponse(&workspacev1.UpdateProjectResponse{Project: pb}), nil
}

func (h *Handler) ListProjects(ctx context.Context, req *connect.Request[workspacev1.ListProjectsRequest]) (*connect.Response[workspacev1.ListProjectsResponse], error) {
	if err := h.requireAdmin(req); err != nil {
		return nil, err
	}
	projects, err := h.svc.ListProjects(ctx)
	if err != nil {
		return nil, errToConnect(err)
	}
	out := make([]*workspacev1.Project, 0, len(projects))
	for _, p := range projects {
		pb, err := projectToProto(p)
		if err != nil {
			return nil, errToConnect(err)
		}
		out = append(out, pb)
	}
	return connect.NewResponse(&workspacev1.ListProjectsResponse{Projects: out}), nil
}
