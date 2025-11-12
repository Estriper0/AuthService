package auth_test

import (
	"context"
	"testing"
	"time"

	"log/slog"

	cache_mocks "github.com/Estriper0/auth_service/internal/cache/mocks"
	"github.com/Estriper0/auth_service/internal/config"
	"github.com/Estriper0/auth_service/internal/jwt"
	"github.com/Estriper0/auth_service/internal/models"
	"github.com/Estriper0/auth_service/internal/repository"
	repo_mocks "github.com/Estriper0/auth_service/internal/repository/mocks"
	"github.com/Estriper0/auth_service/internal/service"
	"github.com/Estriper0/auth_service/internal/service/auth"
	"github.com/golang/mock/gomock"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

const (
	testAccessSecret  = "test-access-secret-1234567890"
	testRefreshSecret = "test-refresh-secret-1234567890"
)

func setupTest(t *testing.T) (*auth.AuthService, *repo_mocks.MockIUserRepository, *cache_mocks.MockCache) {
	ctrl := gomock.NewController(t)
	mockRepo := repo_mocks.NewMockIUserRepository(ctrl)
	mockCache := cache_mocks.NewMockCache(ctrl)

	cfg := &config.Config{
		AccessTokenSecret:  testAccessSecret,
		AccessTokenTTL:     15 * time.Minute,
		RefreshTokenSecret: testRefreshSecret,
		RefreshTokenTTL:    7 * 24 * time.Hour,
	}

	service := auth.New(slog.Default(), cfg, mockRepo, mockCache)
	return service, mockRepo, mockCache
}

func TestAuthService_Login(t *testing.T) {
	svc, mockRepo, _ := setupTest(t)

	hashed, err := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &models.User{
		UUID:     "user-123",
		Email:    "test@example.com",
		PassHash: string(hashed),
		IsAdmin:  false,
	}

	tests := []struct {
		name       string
		email      string
		password   string
		setupMocks func()
		wantTokens bool
		wantErr    error
	}{
		{
			name:     "success: valid credentials",
			email:    "test@example.com",
			password: "correct-password",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetByEmail(gomock.Any(), "test@example.com").
					Return(user, nil)
				mockRepo.EXPECT().
					IsAdmin(gomock.Any(), "user-123").
					Return(false, nil)
			},
			wantTokens: true,
			wantErr:    nil,
		},
		{
			name:     "fail: user not found",
			email:    "unknown@example.com",
			password: "password",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetByEmail(gomock.Any(), "unknown@example.com").
					Return(nil, repository.ErrUserNotFound)
			},
			wantTokens: false,
			wantErr:    service.ErrInvalidCredentials,
		},
		{
			name:     "fail: wrong password",
			email:    "test@example.com",
			password: "wrong-password",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetByEmail(gomock.Any(), "test@example.com").
					Return(user, nil)
				mockRepo.EXPECT().
					IsAdmin(gomock.Any(), "user-123").
					Return(false, nil)
			},
			wantTokens: false,
			wantErr:    service.ErrInvalidCredentials,
		},
		{
			name:     "fail: repo error on GetByEmail",
			email:    "test@example.com",
			password: "password",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetByEmail(gomock.Any(), "test@example.com").
					Return(nil, assert.AnError)
			},
			wantTokens: false,
			wantErr:    service.ErrInternal,
		},
		{
			name:     "fail: repo error on IsAdmin",
			email:    "test@example.com",
			password: "correct-password",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetByEmail(gomock.Any(), "test@example.com").
					Return(user, nil)
				mockRepo.EXPECT().
					IsAdmin(gomock.Any(), "user-123").
					Return(false, assert.AnError)
			},
			wantTokens: false,
			wantErr:    service.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMocks != nil {
				tt.setupMocks()
			}

			tokens, err := svc.Login(context.Background(), tt.email, tt.password)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, tokens)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokens)
				assert.NotEmpty(t, tokens.AccessToken)
				assert.NotEmpty(t, tokens.RefreshToken)

				claims, err := jwt.ValidRefreshToken(tokens.RefreshToken, testRefreshSecret)
				assert.NoError(t, err)
				assert.Equal(t, "user-123", claims["user_id"])
				assert.Equal(t, false, claims["is_admin"])
			}
		})
	}
}

func TestAuthService_Register(t *testing.T) {
	svc, mockRepo, _ := setupTest(t)

	tests := []struct {
		name       string
		email      string
		password   string
		setupMocks func()
		wantUUID   bool
		wantErr    error
	}{
		{
			name:     "success: new user",
			email:    "new@example.com",
			password: "password123",
			setupMocks: func() {
				mockRepo.EXPECT().
					Create(gomock.Any(), "new@example.com", gomock.Any(), false).
					Return("new-uuid-123", nil)
			},
			wantUUID: true,
			wantErr:  nil,
		},
		{
			name:     "fail: user exists",
			email:    "existing@example.com",
			password: "password123",
			setupMocks: func() {
				mockRepo.EXPECT().
					Create(gomock.Any(), "existing@example.com", gomock.Any(), false).
					Return("", repository.ErrUserExists)
			},
			wantUUID: false,
			wantErr:  service.ErrUserExists,
		},
		{
			name:     "fail: repo error",
			email:    "error@example.com",
			password: "password123",
			setupMocks: func() {
				mockRepo.EXPECT().
					Create(gomock.Any(), "error@example.com", gomock.Any(), false).
					Return("", assert.AnError)
			},
			wantUUID: false,
			wantErr:  service.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMocks != nil {
				tt.setupMocks()
			}

			uuid, err := svc.Register(context.Background(), tt.email, tt.password)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Empty(t, uuid)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, uuid)
			}
		})
	}
}

func TestAuthService_IsAdmin(t *testing.T) {
	svc, mockRepo, _ := setupTest(t)

	tests := []struct {
		name       string
		uuid       string
		setupMocks func()
		wantAdmin  bool
		wantErr    error
	}{
		{
			name: "success: admin user",
			uuid: "admin-123",
			setupMocks: func() {
				mockRepo.EXPECT().
					IsAdmin(gomock.Any(), "admin-123").
					Return(true, nil)
			},
			wantAdmin: true,
			wantErr:   nil,
		},
		{
			name: "success: regular user",
			uuid: "user-123",
			setupMocks: func() {
				mockRepo.EXPECT().
					IsAdmin(gomock.Any(), "user-123").
					Return(false, nil)
			},
			wantAdmin: false,
			wantErr:   nil,
		},
		{
			name: "fail: user not found",
			uuid: "unknown-123",
			setupMocks: func() {
				mockRepo.EXPECT().
					IsAdmin(gomock.Any(), "unknown-123").
					Return(false, repository.ErrUserNotFound)
			},
			wantAdmin: false,
			wantErr:   service.ErrUserNotFound,
		},
		{
			name: "fail: repo error",
			uuid: "error-123",
			setupMocks: func() {
				mockRepo.EXPECT().
					IsAdmin(gomock.Any(), "error-123").
					Return(false, assert.AnError)
			},
			wantAdmin: false,
			wantErr:   service.ErrInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMocks != nil {
				tt.setupMocks()
			}

			isAdmin, err := svc.IsAdmin(context.Background(), tt.uuid)

			assert.Equal(t, tt.wantAdmin, isAdmin)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	svc, _, mockCache := setupTest(t)

	validToken := jwt.NewToken("user-123", false, testRefreshSecret, time.Minute)

	tests := []struct {
		name         string
		refreshToken string
		setupMocks   func()
		wantErr      error
	}{
		{
			name:         "fail: already blacklisted",
			refreshToken: "blacklisted-token",
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), "blacklisted-token").
					Return("true", nil)
			},
			wantErr: service.ErrRefreshBlacklist,
		},
		{
			name:         "fail: invalid token",
			refreshToken: "invalid.jwt.token",
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), "invalid.jwt.token").
					Return("", redis.Nil)
			},
			wantErr: service.ErrInvalidToken,
		},
		{
			name:         "fail: cache set error",
			refreshToken: validToken,
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), validToken).
					Return("", redis.Nil)
				mockCache.EXPECT().
					Set(gomock.Any(), validToken, true, gomock.Any()).
					Return(assert.AnError)
			},
			wantErr: service.ErrInternal,
		},
		{
			name:         "success: logout",
			refreshToken: validToken,
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), validToken).
					Return("", redis.Nil)
				mockCache.EXPECT().
					Set(gomock.Any(), validToken, true, gomock.Any()).
					Return(nil)
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMocks != nil {
				tt.setupMocks()
			}

			err := svc.Logout(context.Background(), tt.refreshToken)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_Refresh(t *testing.T) {
	svc, _, mockCache := setupTest(t)

	validToken := jwt.NewToken("user-123", false, testRefreshSecret, time.Minute)

	tests := []struct {
		name         string
		refreshToken string
		setupMocks   func()
		wantTokens   bool
		wantErr      error
	}{
		{
			name:         "fail: blacklisted",
			refreshToken: "blacklisted-token",
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), "blacklisted-token").
					Return("true", nil)
			},
			wantTokens: false,
			wantErr:    service.ErrRefreshBlacklist,
		},
		{
			name:         "fail: invalid token",
			refreshToken: "invalid.jwt.token",
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), "invalid.jwt.token").
					Return("", redis.Nil)
			},
			wantTokens: false,
			wantErr:    service.ErrInvalidToken,
		},
		{
			name:         "fail: cache set error",
			refreshToken: validToken,
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), validToken).
					Return("", redis.Nil)
				mockCache.EXPECT().
					Set(gomock.Any(), validToken, true, gomock.Any()).
					Return(assert.AnError)
			},
			wantTokens: false,
			wantErr:    service.ErrInternal,
		},
		{
			name:         "success: refresh",
			refreshToken: validToken,
			setupMocks: func() {
				mockCache.EXPECT().
					Get(gomock.Any(), validToken).
					Return("", redis.Nil)
				mockCache.EXPECT().
					Set(gomock.Any(), validToken, true, gomock.Any()).
					Return(nil)
			},
			wantTokens: true,
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupMocks != nil {
				tt.setupMocks()
			}

			tokens, err := svc.Refresh(context.Background(), tt.refreshToken)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, tokens)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokens)
				assert.NotEmpty(t, tokens.AccessToken)
				assert.NotEmpty(t, tokens.RefreshToken)

				claims, err := jwt.ValidRefreshToken(tokens.RefreshToken, testRefreshSecret)
				assert.NoError(t, err)
				assert.Equal(t, "user-123", claims["user_id"])
				assert.Equal(t, false, claims["is_admin"])
			}
		})
	}
}
