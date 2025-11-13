package tests

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/Estriper0/auth_service/internal/config"
	"github.com/golang-migrate/migrate/v4"
	migrate_pg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestMain(m *testing.M) {
	os.Setenv("APP_ENV", "test")

	os.Setenv("DB_NAME", "db_test")
	os.Setenv("DB_USER", "postgres")
	os.Setenv("DB_PASSWORD", "12345")

	m.Run()
}

type TestSuite struct {
	suite.Suite

	ctx         context.Context
	db          *sql.DB
	pgContainer *postgres.PostgresContainer
}

func TestRepositoriesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	suite.Run(t, new(TestSuite))
}

func (s *TestSuite) SetupSuite() {
	ctx := context.Background()
	config := config.New()
	config.Port = 55555

	pgContainer, err := postgres.Run(ctx,
		"postgres:18.0-alpine3.22",
		postgres.WithDatabase(config.DB.DbName),
		postgres.WithUsername(config.DB.DbUser),
		postgres.WithPassword(config.DB.DbPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	s.Require().NoError(err)

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	s.Require().NoError(err)

	db, err := sql.Open("postgres", connStr)
	s.Require().NoError(err)

	_, err = db.Exec("CREATE SCHEMA IF NOT EXISTS auth")
	if err != nil {
		panic(err)
	}

	driver, err := migrate_pg.WithInstance(db, &migrate_pg.Config{
		MigrationsTable: "auth.migrations",
		SchemaName:      "auth",
	})
	s.Require().NoError(err)

	m, err := migrate.NewWithDatabaseInstance(
		"file://../migrations",
		"postgres", driver)
	s.Require().NoError(err)

	m.Up()

	s.ctx = ctx
	s.db = db
	s.pgContainer = pgContainer
}

func (s *TestSuite) TearDownSuite() {
	s.db.Close()
	s.pgContainer.Terminate(s.ctx)
}

func (s *TestSuite) SetupTest() {
	_, err := s.db.ExecContext(s.ctx, "TRUNCATE TABLE auth.users CASCADE;")
	s.Require().NoError(err)
}
