package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Estriper0/auth_service/internal/config"
	"github.com/Estriper0/auth_service/internal/jwt"
	"github.com/Estriper0/auth_service/internal/repository"
	"github.com/Estriper0/auth_service/internal/service"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	logger   *slog.Logger
	config   *config.Config
	userRepo repository.IUserRepository
	appRepo  repository.IAppRepository
}

func New(logger *slog.Logger, config *config.Config, userRepo repository.IUserRepository, appRepo repository.IAppRepository) *AuthService {
	return &AuthService{
		logger:   logger,
		config:   config,
		userRepo: userRepo,
		appRepo:  appRepo,
	}
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
	appId int32,
) (string, error) {
	s.logger.Info(
		"Logginnig user",
		slog.String("email", email),
	)

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			s.logger.Warn(
				"User not found",
				slog.String("email", email),
			)
			return "", service.ErrInvalidCredentials
		}
		s.logger.Error("Failed to get user")
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		s.logger.Info("Invalid credentials")
		return "", service.ErrInvalidCredentials
	}

	app, err := s.appRepo.GetByID(ctx, appId)
	if err != nil {
		if errors.Is(err, repository.ErrAppNotFound) {
			s.logger.Warn(
				"App not found",
				slog.Int("app_id", int(appId)),
			)
			return "", repository.ErrAppNotFound
		}
		s.logger.Warn("Failed to get app")
		return "", err
	}

	s.logger.Info("User logged in successfully")

	return jwt.NewToken(user, app, s.config.TokenTTL), nil
}

func (s *AuthService) Register(
	ctx context.Context,
	email string,
	password string,
) (string, error) {
	s.logger.Info(
		"Registering user",
		slog.String("email", email),
	)

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("Failed to generate password hash")
		return "", err
	}

	uuid, err := s.userRepo.Create(ctx, email, string(passHash))
	if err != nil {
		if errors.Is(err, repository.ErrUserExists) {
			s.logger.Warn(
				"User exists",
				slog.String("email", email),
			)
			return "", err
		}
		s.logger.Error("Failed to save user")
		return "", err
	}
	return uuid, nil
}

func (s *AuthService) IsAdmin(
	ctx context.Context,
	uuid string,
) (bool, error) {
	s.logger.Info(
		"Checking user is admin",
		slog.String("uuid", uuid),
	)

	isAdmin, err := s.userRepo.IsAdmin(ctx, uuid)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			s.logger.Warn(
				"User not found",
				slog.String("uuid", uuid),
			)
			return false, err
		}
		return false, err
	}
	s.logger.Info(
		"Successfully check user is admin",
		slog.String("uuid", uuid),
		slog.Bool("is_admin", isAdmin),
	)
	return isAdmin, nil
}
