package config

import (
	"flag"
	"os"
	"time"

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
	var path string

	flag.StringVar(&path, "config", "", "path to config")
	flag.Parse()

	path_env, ok := os.LookupEnv("CONFIG_PATH")
	if ok {
		path = path_env
	}

	if path == "" {
		panic("empty config path")
	}

	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		panic(err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		panic(err)
	}

	return &config
}
