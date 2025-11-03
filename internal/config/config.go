package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	Env                string        `mapstructure:"env"`
	Port               int           `mapstructure:"port"`
	Timeout            time.Duration `mapstructure:"timeout"`
	AccessTokenTTL     time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL    time.Duration `mapstructure:"refresh_token_ttl"`
	AccessTokenSecret  string        `mapstructure:"access_token_secret"`
	RefreshTokenSecret string        `mapstructure:"refresh_token_secret"`
	DB                 Database      `mapstructure:"database"`
	Redis              Redis         `mapstructure:"redis"`
}

type Database struct {
	DbHost     string `mapstructure:"dbhost"`
	DbPort     string `mapstructure:"dbport"`
	DbUser     string `mapstructure:"dbuser"`
	DbPassword string `mapstructure:"dbpassword"`
	DbName     string `mapstructure:"dbname"`
	SSLMode    string `mapstructure:"sslmode"`
}

type Redis struct {
	Addr     string        `mapstructure:"addr"`
	CacheTTL time.Duration `mapstructure:"cache_ttl"`
	Password string        `mapstructure:"password"`
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
	viper.BindEnv("redis.addr", "REDIS_ADDR")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.BindEnv("access_token_secret", "ACCESS_TOKEN_SECRET")
	viper.BindEnv("refresh_token_secret", "REFRESH_TOKEN_SECRET")
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
