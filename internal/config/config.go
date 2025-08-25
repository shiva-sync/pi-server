package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	// Server
	Port     int    `json:"port"`
	LogLevel string `json:"log_level"`

	// S3 Configuration
	S3Endpoint        string `json:"s3_endpoint"`
	S3Region          string `json:"s3_region"`
	S3Bucket          string `json:"s3_bucket"`
	S3AccessKeyID     string `json:"s3_access_key_id"`
	S3SecretAccessKey string `json:"s3_secret_access_key"`

	// Discord OAuth
	DiscordClientID       string `json:"discord_client_id"`
	DiscordClientSecret   string `json:"discord_client_secret"`
	DiscordRedirectURI    string `json:"discord_redirect_uri"`
	DiscordGuildID        string `json:"discord_guild_id"`
	DiscordRequiredRoleID string `json:"discord_required_role_id"`

	// JWT
	JWTSigningKey []byte `json:"-"`

	// Admin
	AdminBearerToken  []byte `json:"-"`
	AdminUsername     string `json:"admin_username"`
	AdminPasswordHash string `json:"admin_password_hash"`
	AdminSessionKey   []byte `json:"-"`
	AdminUIEnabled    bool   `json:"admin_ui_enabled"`

	// Federation (Stretch Goal)
	FederationEnabled    bool     `json:"federation_enabled"`
	FederationServerCert string   `json:"federation_server_cert"`
	FederationServerKey  string   `json:"federation_server_key"`
	FederationCACert     string   `json:"federation_ca_cert"`
	FederationToken      string   `json:"federation_token"`
	FederationPeers      []string `json:"federation_peers"`

	// CORS
	AllowOrigin string `json:"allow_origin"`
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	// Try to load .env file if it exists
	_ = godotenv.Load()

	cfg := &Config{
		Port:              getEnvInt("PORT", 8080),
		LogLevel:          getEnvString("LOG_LEVEL", "info"),
		S3Endpoint:        getEnvString("S3_ENDPOINT", ""),
		S3Region:          getEnvString("S3_REGION", ""),
		S3Bucket:          getEnvString("S3_BUCKET", ""),
		S3AccessKeyID:     getEnvString("S3_ACCESS_KEY_ID", ""),
		S3SecretAccessKey: getEnvString("S3_SECRET_ACCESS_KEY", ""),

		DiscordClientID:       getEnvString("DISCORD_CLIENT_ID", ""),
		DiscordClientSecret:   getEnvString("DISCORD_CLIENT_SECRET", ""),
		DiscordRedirectURI:    getEnvString("DISCORD_REDIRECT_URI", ""),
		DiscordGuildID:        getEnvString("DISCORD_GUILD_ID", ""),
		DiscordRequiredRoleID: getEnvString("DISCORD_REQUIRED_ROLE_ID", ""),

		AdminUsername:     getEnvString("ADMIN_USERNAME", "admin"),
		AdminPasswordHash: getEnvString("ADMIN_PASSWORD_HASH", ""),
		AdminUIEnabled:    getEnvBool("ADMIN_UI_ENABLED", false),

		FederationEnabled:    getEnvBool("FEDERATION_ENABLED", false),
		FederationServerCert: getEnvString("FEDERATION_SERVER_CERT", ""),
		FederationServerKey:  getEnvString("FEDERATION_SERVER_KEY", ""),
		FederationCACert:     getEnvString("FEDERATION_CA_CERT", ""),
		FederationToken:      getEnvString("FEDERATION_TOKEN", ""),

		AllowOrigin: getEnvString("ALLOW_ORIGIN", ""),
	}

	// Parse Federation Peers
	peersStr := getEnvString("FEDERATION_PEERS", "")
	if peersStr != "" {
		cfg.FederationPeers = strings.Split(peersStr, ",")
		for i, peer := range cfg.FederationPeers {
			cfg.FederationPeers[i] = strings.TrimSpace(peer)
		}
	}

	// Parse base64 encoded keys
	var err error
	cfg.JWTSigningKey, err = parseBase64Key("JWT_SIGNING_KEY", true)
	if err != nil {
		return nil, fmt.Errorf("JWT_SIGNING_KEY: %w", err)
	}

	cfg.AdminBearerToken, err = parseBase64Key("ADMIN_BEARER_TOKEN", true)
	if err != nil {
		return nil, fmt.Errorf("ADMIN_BEARER_TOKEN: %w", err)
	}

	cfg.AdminSessionKey, err = parseBase64Key("ADMIN_SESSION_KEY", cfg.AdminUIEnabled)
	if err != nil {
		return nil, fmt.Errorf("ADMIN_SESSION_KEY: %w", err)
	}

	// Validate required fields
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	required := map[string]string{
		"S3_REGION":                  c.S3Region,
		"S3_BUCKET":                  c.S3Bucket,
		"S3_ACCESS_KEY_ID":           c.S3AccessKeyID,
		"S3_SECRET_ACCESS_KEY":       c.S3SecretAccessKey,
		"DISCORD_CLIENT_ID":          c.DiscordClientID,
		"DISCORD_CLIENT_SECRET":      c.DiscordClientSecret,
		"DISCORD_REDIRECT_URI":       c.DiscordRedirectURI,
		"DISCORD_GUILD_ID":           c.DiscordGuildID,
		"DISCORD_REQUIRED_ROLE_ID":   c.DiscordRequiredRoleID,
	}

	for key, value := range required {
		if value == "" {
			return fmt.Errorf("required environment variable %s is not set", key)
		}
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("invalid log level: %s (must be debug, info, or warn)", c.LogLevel)
	}

	return nil
}

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func parseBase64Key(envVar string, required bool) ([]byte, error) {
	value := os.Getenv(envVar)
	if value == "" {
		if required {
			return nil, fmt.Errorf("required environment variable %s is not set", envVar)
		}
		return nil, nil
	}

	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding for %s: %w", envVar, err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("%s must be exactly 32 bytes when base64 decoded, got %d bytes", envVar, len(key))
	}

	return key, nil
}
