package app

import (
	"log/slog"

	rd "github.com/Estriper0/auth_service/internal/cache/redis"
	"github.com/Estriper0/auth_service/internal/config"
	user_repo "github.com/Estriper0/auth_service/internal/repository/user"
	"github.com/Estriper0/auth_service/internal/server"
	auth_service "github.com/Estriper0/auth_service/internal/service/auth"
	db "github.com/Estriper0/auth_service/pkg/database"
	"github.com/redis/go-redis/v9"
)

type App struct {
	logger     *slog.Logger
	config     *config.Config
	grpcServer *server.GRPCServer
}

func New(
	logger *slog.Logger,
	config *config.Config,
) *App {
	db := db.GetDB(&config.DB)

	userRepo := user_repo.New(db)
	redisClient := redis.NewClient(&redis.Options{Addr: config.Redis.Addr, Password: config.Redis.Password})
	cache := rd.New(redisClient)
	authSevice := auth_service.New(logger, config, userRepo, cache)
	grpcServer := server.New(logger, config, authSevice)

	return &App{
		logger:     logger,
		config:     config,
		grpcServer: grpcServer,
	}
}

func (a *App) Run() {
	a.logger.Info("Start application")

	a.grpcServer.Run()
}

func (a *App) Stop() {
	a.grpcServer.Stop()

	a.logger.Info("Stop application")
}
