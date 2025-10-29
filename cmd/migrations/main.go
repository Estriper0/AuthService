package main

import (
	"database/sql"
	"fmt"

	"github.com/Estriper0/auth_service/internal/config"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

func main() {
	config := config.New()

	db, err := sql.Open(
		"postgres",
		fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=%s",
			config.DB.DbUser,
			config.DB.DbPassword,
			config.DB.DbHost,
			config.DB.DbPort,
			config.DB.DbName,
			config.DB.SSLMode,
		),
	)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		panic(err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		panic(err)
	}
	m.Up()
	fmt.Println("Migrations complete!")
}
