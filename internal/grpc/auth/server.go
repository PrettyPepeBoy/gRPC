package auth

import (
	"context"
	ssov1 "github.com/PrettyPepeBoy/protos/gen/go/sso"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, email, password string, appId int32) (token string, err error)
	RegisterNewUser(ctx context.Context, email, password string) (userId int64, err error)
	IsAdmin(ctx context.Context, userId int64) (isAdmin bool, err error)
}
type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	token, err := s.auth.Login(ctx, req.Email, req.Password, req.AppId)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal problem")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverAPI) RegisterNewUser(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid email")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid password")
	}
	userId, err := s.auth.RegisterNewUser(ctx, req.Email, req.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal problem")
	}

	return &ssov1.RegisterResponse{
		UserId: userId,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if req.GetUserId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid Id")
	}
	ok, err := s.auth.IsAdmin(ctx, req.UserId)
	if err != nil {
		return nil, status.Error(codes.Internal, "internal problem")
	}
	return &ssov1.IsAdminResponse{
		IsAdmin: ok,
	}, nil
}
