package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/Estriper0/auth_service/internal/cache"
	"github.com/Estriper0/auth_service/internal/config"
	"github.com/Estriper0/auth_service/internal/jwt"
	"github.com/Estriper0/auth_service/internal/repository"
	"github.com/Estriper0/auth_service/internal/service"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	logger   *slog.Logger
	config   *config.Config
	userRepo repository.IUserRepository
	cache    cache.Cache
}

func New(logger *slog.Logger, config *config.Config, userRepo repository.IUserRepository, cache cache.Cache) *AuthService {
	return &AuthService{
		logger:   logger,
		config:   config,
		userRepo: userRepo,
		cache:    cache,
	}
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
) (string, string, error) {
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
			return "", "", service.ErrInvalidCredentials
		}
		s.logger.Error("Failed to get user")
		return "", "", service.ErrInternal
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		s.logger.Info("Invalid credentials")
		return "", "", service.ErrInvalidCredentials
	}

	s.logger.Info("User logged in successfully")

	return jwt.NewAccessToken(user.UUID, s.config.AccessTokenSecret, s.config.AccessTokenTTL),
		jwt.NewRefreshToken(user.UUID, s.config.RefreshTokenSecret, s.config.RefreshTokenTTL), nil
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
		return "", service.ErrInternal
	}

	uuid, err := s.userRepo.Create(ctx, email, string(passHash))
	if err != nil {
		if errors.Is(err, repository.ErrUserExists) {
			s.logger.Warn(
				"User exists",
				slog.String("email", email),
			)
			return "", service.ErrUserExists
		}
		s.logger.Error(
			"Failed to save user",
			slog.String("error", err.Error()),
		)
		return "", service.ErrInternal
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
			return false, service.ErrUserNotFound
		}
		return false, service.ErrInternal
	}
	s.logger.Info(
		"Successfully check user is admin",
		slog.String("uuid", uuid),
		slog.Bool("is_admin", isAdmin),
	)

	s.logger.Info("Successfully added to cache")

	return isAdmin, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	_, err := s.cache.Get(ctx, refreshToken)
	if err != redis.Nil {
		s.logger.Warn(
			"Token in blacklist",
			slog.String("refresh_token", refreshToken),
		)
		return service.ErrInvalidToken
	}
	user_id, ok := jwt.ValidRefreshToken(refreshToken, s.config.RefreshTokenSecret)
	if !ok {
		s.logger.Warn(
			"Token is not valid",
			slog.String("refresh_token", refreshToken),
		)
		return service.ErrInvalidToken
	}
	err = s.cache.Set(ctx, refreshToken, true, s.config.RefreshTokenTTL)
	if err != nil {
		s.logger.Error(
			"Error adding to blacklist",
			slog.String("refresh_token", refreshToken),
		)
		return service.ErrRefreshBlacklist
	}
	s.logger.Error(
		"Successfully logout user",
		slog.String("user_id", user_id),
	)
	return nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (string, string, error) {
	_, err := s.cache.Get(ctx, refreshToken)
	if err != redis.Nil {
		s.logger.Warn(
			"Token in blacklist",
			slog.String("refresh_token", refreshToken),
		)
		return "", "", service.ErrInvalidToken
	}
	user_id, ok := jwt.ValidRefreshToken(refreshToken, s.config.RefreshTokenSecret)
	if !ok {
		s.logger.Warn(
			"Token is not valid",
			slog.String("refresh_token", refreshToken),
		)
		return "", "", service.ErrInvalidToken
	}

	err = s.cache.Set(ctx, refreshToken, true, s.config.RefreshTokenTTL)
	if err != nil {
		s.logger.Error(
			"Error adding to blacklist",
			slog.String("refresh_token", refreshToken),
		)
		return "", "", service.ErrRefreshBlacklist
	}

	return jwt.NewAccessToken(user_id, s.config.AccessTokenSecret, s.config.AccessTokenTTL),
		jwt.NewRefreshToken(user_id, s.config.RefreshTokenSecret, s.config.RefreshTokenTTL), nil
}
