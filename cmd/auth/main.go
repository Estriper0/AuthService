package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/Estriper0/auth_service/internal/app"
	"github.com/Estriper0/auth_service/internal/config"
	"github.com/Estriper0/auth_service/pkg/logger"
)

func main() {
	config := config.New()

	logger := logger.GetLogger(config.Env)

	app := app.New(logger, config)
	go app.Run()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	logger.Info("Received shutdown signal. Initiating graceful shutdown...")

	app.Stop()
}
