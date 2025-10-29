package auth

import (
	"context"

	"github.com/Estriper0/auth_service/internal/service"
	pb "github.com/Estriper0/protobuf_eventhub/gen/auth"
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
		return nil, err
	}

	token, err := s.authService.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &pb.LoginResponse{
		Token: token,
	}, nil
}

func (s *AuthGRPCService) Register(
	ctx context.Context,
	req *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	if err := validateRegister(req); err != nil {
		return nil, err
	}

	uuid, err := s.authService.Register(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
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
		return nil, err
	}

	isAdmin, err := s.authService.IsAdmin(ctx, req.GetUserUuid())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &pb.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func validateLogin(req *pb.LoginRequest) error {
	if !govalidator.IsEmail(req.GetEmail()) {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == 0 {
		return status.Error(codes.InvalidArgument, "app_id is required")
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
