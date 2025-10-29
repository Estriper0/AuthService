package db

import (
	"database/sql"
	"fmt"

	"github.com/Estriper0/auth_service/internal/config"
	_ "github.com/lib/pq"
)

func GetDB(config *config.Database) *sql.DB {
	db, err := sql.Open(
		"postgres",
		fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
			config.DbHost,
			config.DbPort,
			config.DbUser,
			config.DbPassword,
			config.DbName,
			config.SSLMode,
		),
	)
	if err != nil {
		panic(err)
	}
	if err := db.Ping(); err != nil {
		panic(err)
	}

	return db
}
