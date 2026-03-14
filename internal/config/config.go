package config

import (
	"errors"
	"os"
)

// Config holds all environment-based configuration for the server.
type Config struct {
	Addr      string
	DBURL     string
	Platform  string
	JWTSecret string
	PolkaKey  string
}

// Load reads Config values from environment variables.
// It returns an error if required variables are missing.
func Load() (*Config, error) {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		return nil, errors.New("DB_URL environment variable not set")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET environment variable not set")
	}

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		platform = "dev"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8888"
	}

	return &Config{
		Addr:      ":" + port,
		DBURL:     dbURL,
		Platform:  platform,
		JWTSecret: jwtSecret,
		PolkaKey:  os.Getenv("POLKA_KEY"),
	}, nil
}
