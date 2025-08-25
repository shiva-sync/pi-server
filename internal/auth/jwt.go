package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents JWT claims for authenticated users
type Claims struct {
	UserID   string   `json:"sub"`
	GuildID  string   `json:"guild_id"`
	Roles    []string `json:"roles"`
	Username string   `json:"username"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token creation and validation
type JWTManager struct {
	signingKey []byte
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(signingKey []byte) *JWTManager {
	return &JWTManager{
		signingKey: signingKey,
	}
}

// GenerateToken creates a new JWT token for a user
func (j *JWTManager) GenerateToken(userID, guildID, username string, roles []string) (string, error) {
	claims := Claims{
		UserID:   userID,
		GuildID:  guildID,
		Roles:    roles,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.signingKey)
}

// ValidateToken validates and parses a JWT token
func (j *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.signingKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// EncryptRefreshToken encrypts a Discord refresh token for storage
func (j *JWTManager) EncryptRefreshToken(refreshToken string) (string, error) {
	block, err := aes.NewCipher(j.signingKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(refreshToken), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptRefreshToken decrypts a stored refresh token
func (j *JWTManager) DecryptRefreshToken(encryptedToken string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedToken)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(j.signingKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
