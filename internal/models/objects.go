package models

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PresignPutRequest represents a request for a presigned PUT URL
type PresignPutRequest struct {
	SHA256       string `json:"sha256" binding:"required"`
	Size         int64  `json:"size" binding:"required,min=1,max=524288000"` // Max 500MB
	ContentType  string `json:"content_type"`
}

// PresignPutResponse represents the response for a presigned PUT URL
type PresignPutResponse struct {
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	ExpiresIn int               `json:"expires_in"`
}

// PresignGetRequest represents a request for a presigned GET URL
type PresignGetRequest struct {
	SHA256 string `json:"sha256" binding:"required"`
}

// PresignGetResponse represents the response for a presigned GET URL
type PresignGetResponse struct {
	URL       string `json:"url"`
	ExpiresIn int    `json:"expires_in"`
}

// ObjectMeta represents metadata for an uploaded object
type ObjectMeta struct {
	Uploader  string    `json:"uploader" validate:"required,min=1,max=255"`
	Source    string    `json:"source,omitempty" validate:"max=500"`
	Licence   string    `json:"licence" validate:"required,oneof=unknown free paid own_work restricted"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
}

// ValidateSHA256 validates that a string is a valid SHA256 hash
func ValidateSHA256(hash string) error {
	// Check length (64 characters for SHA256)
	if len(hash) != 64 {
		return fmt.Errorf("SHA256 hash must be exactly 64 characters, got %d", len(hash))
	}

	// Check if it's valid hex
	if _, err := hex.DecodeString(hash); err != nil {
		return fmt.Errorf("SHA256 hash must be valid hexadecimal: %w", err)
	}

	// Check if it's lowercase
	if matched, _ := regexp.MatchString("^[a-f0-9]{64}$", hash); !matched {
		return fmt.Errorf("SHA256 hash must be lowercase hexadecimal")
	}

	return nil
}

// NormalizeSHA256 ensures a SHA256 hash is lowercase
func NormalizeSHA256(hash string) string {
	return strings.ToLower(hash)
}
