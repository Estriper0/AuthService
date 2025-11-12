package auth

import (
	"context"
	"errors"

	"github.com/Estriper0/auth_service/internal/service"
	pb "github.com/Estriper0/protobuf/gen/auth"
	"github.com/asaskevich/govalidator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthGRPCService struct {
	pb.UnimplementedAuthServer
	authService service.IAuthService
}

func Register(gRPC *grpc.Server, authService service.IAuthService) {
	pb.RegisterAuthServer(gRPC, &AuthGRPCService{authService: authService})
}

func (s *AuthGRPCService) Login(
	ctx context.Context,
	req *pb.LoginRequest,
) (*pb.LoginResponse, error) {
	if err := validateLogin(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	tokens, err := s.authService.Login(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &pb.LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (s *AuthGRPCService) Register(
	ctx context.Context,
	req *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	uuid, err := s.authService.Register(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user exists")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &pb.RegisterResponse{
		UserUuid: uuid,
	}, nil
}

func (s *AuthGRPCService) IsAdmin(
	ctx context.Context,
	req *pb.IsAdminRequest,
) (*pb.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	isAdmin, err := s.authService.IsAdmin(ctx, req.GetUserUuid())
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &pb.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func (s *AuthGRPCService) Logout(
	ctx context.Context,
	req *pb.LogoutRequest,
) (*pb.EmptyRequest, error) {
	err := s.authService.Logout(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, service.ErrRefreshBlacklist) {
			return nil, status.Error(codes.Internal, "internal error")
		}
	}
	return &pb.EmptyRequest{}, nil
}

func (s *AuthGRPCService) Refresh(
	ctx context.Context,
	req *pb.RefreshRequest,
) (*pb.RefreshResponse, error) {
	tokens, err := s.authService.Refresh(ctx, req.RefreshToken)
	if err != nil {
		if errors.Is(err, service.ErrInvalidToken) {
			return nil, status.Error(codes.InvalidArgument, "invalid token")
		}
		if errors.Is(err, service.ErrRefreshBlacklist) {
			return nil, status.Error(codes.Internal, "internal error")
		}
	}
	return &pb.RefreshResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func validateLogin(req *pb.LoginRequest) error {
	if !govalidator.IsEmail(req.GetEmail()) {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateRegister(req *pb.RegisterRequest) error {
	if !govalidator.IsEmail(req.GetEmail()) {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateIsAdmin(req *pb.IsAdminRequest) error {
	if !govalidator.IsUUID(req.GetUserUuid()) {
		return status.Error(codes.InvalidArgument, "user_uuid is required")
	}
	return nil
}
