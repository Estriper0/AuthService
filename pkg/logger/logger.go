package logger

import (
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
)

func GetLogger(env string) *slog.Logger {
	switch env {
	case "local":
		return slog.New(
			tint.NewHandler(
				os.Stdout,
				&tint.Options{
					Level:      slog.LevelDebug,
					TimeFormat: time.Kitchen,
				},
			),
		)
	case "prod":
		return slog.New(
			slog.NewJSONHandler(
				os.Stdout,
				&slog.HandlerOptions{
					Level: slog.LevelDebug,
				},
			),
		)
	}
	return nil
}
