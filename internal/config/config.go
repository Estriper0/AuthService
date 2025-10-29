package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	Env      string        `mapstructure:"env"`
	Port     int           `mapstructure:"port"`
	Timeout  time.Duration `mapstructure:"timeout"`
	TokenTTL time.Duration `mapstructure:"token_ttl"`
	DB       Database      `mapstructure:"database"`
}

type Database struct {
	DbHost     string `mapstructure:"dbhost"`
	DbPort     string `mapstructure:"dbport"`
	DbUser     string `mapstructure:"dbuser"`
	DbPassword string `mapstructure:"dbpassword"`
	DbName     string `mapstructure:"dbname"`
	SSLMode    string `mapstructure:"sslmode"`
}

func New() *Config {
	_ = godotenv.Load(".env")

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "local"
	}

	viper.AddConfigPath("./configs")
	viper.AddConfigPath("../configs")
	viper.SetConfigName(env)
	viper.SetConfigType("yaml")

	viper.SetDefault("env", env)
	viper.SetDefault("database.dbport", 5432)
	viper.SetDefault("database.dbhost", "localhost")

	viper.BindEnv("database.dbhost", "DB_HOST")
	viper.BindEnv("database.dbport", "DB_PORT")
	viper.BindEnv("database.dbname", "DB_NAME")
	viper.BindEnv("database.dbuser", "DB_USER")
	viper.BindEnv("database.dbpassword", "DB_PASSWORD")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		panic(err)
	}

	return &config
}
