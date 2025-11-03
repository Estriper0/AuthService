package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"log/slog"

	redis "github.com/Estriper0/auth_service/internal/cache/mocks"
	"github.com/Estriper0/auth_service/internal/config"
	jwt_service "github.com/Estriper0/auth_service/internal/jwt"
	"github.com/Estriper0/auth_service/internal/models"
	"github.com/Estriper0/auth_service/internal/repository"
	"github.com/Estriper0/auth_service/internal/repository/database/mocks"
	srv "github.com/Estriper0/auth_service/internal/service"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthService_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockIUserRepository(ctrl)
	mockRedis := redis.NewMockCache(ctrl)

	logger := slog.Default()
	cfg := &config.Config{
		AccessTokenTTL:    24 * time.Hour,
		AccessTokenSecret: "secret",
	}

	service := New(logger, cfg, mockUserRepo, mockRedis)

	ctx := context.Background()

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("validpassword"), bcrypt.DefaultCost)
	user := models.User{
		UUID:     "user-123",
		Email:    "test@example.com",
		PassHash: string(hashedPassword),
	}

	tests := []struct {
		name          string
		email         string
		password      string
		setupMocks    func()
		expectedToken string
		expectedErr   error
	}{
		{
			name:     "successful login",
			email:    "test@example.com",
			password: "validpassword",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					GetByEmail(ctx, "test@example.com").
					Return(user, nil)
			},
			expectedToken: jwt_service.NewAccessToken(user, cfg.AccessTokenSecret, cfg.AccessTokenTTL),
			expectedErr:   nil,
		},
		{
			name:     "invalid password",
			email:    "test@example.com",
			password: "wrongpassword",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					GetByEmail(ctx, "test@example.com").
					Return(user, nil)
			},
			expectedToken: jwt_service.NewAccessToken(user, cfg.AccessTokenSecret, cfg.AccessTokenTTL),
			expectedErr:   srv.ErrInvalidCredentials,
		},
		{
			name:     "user not found",
			email:    "unknown@example.com",
			password: "anypassword",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					GetByEmail(ctx, "unknown@example.com").
					Return(models.User{}, repository.ErrUserNotFound)
			},
			expectedToken: jwt_service.NewAccessToken(user, cfg.AccessTokenSecret, cfg.AccessTokenTTL),
			expectedErr:   srv.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			token, _, err := service.Login(ctx, tt.email, tt.password)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
				tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
					return []byte(cfg.AccessTokenSecret), nil
				})
				require.NoError(t, err)

				claims, ok := tokenParsed.Claims.(jwt.MapClaims)
				require.True(t, ok)

				assert.Equal(t, user.UUID, claims["user_id"])
			}
		})
	}
}

func TestAuthService_Register(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockIUserRepository(ctrl)
	mockRedis := redis.NewMockCache(ctrl)

	logger := slog.Default()
	cfg := &config.Config{}

	service := New(logger, cfg, mockUserRepo, mockRedis)

	ctx := context.Background()

	tests := []struct {
		name         string
		email        string
		password     string
		setupMocks   func()
		expectedUUID string
		expectedErr  error
	}{
		{
			name:     "successful registration",
			email:    "newuser@example.com",
			password: "securepassword",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					Create(ctx, "newuser@example.com", gomock.Any()).
					Return("new-uuid-123", nil)
			},
			expectedUUID: "new-uuid-123",
			expectedErr:  nil,
		},
		{
			name:     "user already exists",
			email:    "existing@example.com",
			password: "password",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					Create(ctx, "existing@example.com", gomock.Any()).
					Return("", repository.ErrUserExists)
			},
			expectedUUID: "",
			expectedErr:  repository.ErrUserExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMocks != nil {
				tt.setupMocks()
			}

			uuid, err := service.Register(ctx, tt.email, tt.password)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				if tt.expectedErr.Error() != "" {
					assert.EqualError(t, err, tt.expectedErr.Error())
				}
				assert.Empty(t, uuid)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUUID, uuid)
			}
		})
	}
}

func TestAuthService_IsAdmin(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserRepo := mocks.NewMockIUserRepository(ctrl)
	mockRedis := redis.NewMockCache(ctrl)

	logger := slog.Default()
	cfg := &config.Config{}

	service := New(logger, cfg, mockUserRepo, mockRedis)

	ctx := context.Background()

	tests := []struct {
		name        string
		uuid        string
		setupMocks  func()
		expected    bool
		expectedErr error
	}{
		{
			name: "user is admin",
			uuid: "admin-123",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					IsAdmin(ctx, "admin-123").
					Return(true, nil)
			},
			expected:    true,
			expectedErr: nil,
		},
		{
			name: "user is not admin",
			uuid: "user-456",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					IsAdmin(ctx, "user-456").
					Return(false, nil)
			},
			expected:    false,
			expectedErr: nil,
		},
		{
			name: "user not found",
			uuid: "unknown-789",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					IsAdmin(ctx, "unknown-789").
					Return(false, repository.ErrUserNotFound)
			},
			expected:    false,
			expectedErr: repository.ErrUserNotFound,
		},
		{
			name: "database error",
			uuid: "fail-999",
			setupMocks: func() {
				mockUserRepo.EXPECT().
					IsAdmin(ctx, "fail-999").
					Return(false, errors.New("query failed"))
			},
			expected:    false,
			expectedErr: srv.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			isAdmin, err := service.IsAdmin(ctx, tt.uuid)

			assert.Equal(t, tt.expected, isAdmin)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
