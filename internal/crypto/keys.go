package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// KeyManager handles group keys and user keypairs
type KeyManager struct {
	// In-memory storage for this implementation
	// In production, these would be stored in a database
	userPublicKeys map[string][]byte    // userID -> X25519 public key
	groupKeys      map[string]*GroupKey // date -> group key
}

// GroupKey represents a daily group key for the guild
type GroupKey struct {
	Key       []byte    `json:"key"`        // 32-byte ChaCha20-Poly1305 key
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// UserKeyPair represents a user's X25519 keypair
type UserKeyPair struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
}

// WrappedGroupKey represents a group key encrypted for a specific user
type WrappedGroupKey struct {
	EncryptedKey []byte `json:"ek"`
	Algorithm    string `json:"alg"`
	KeyID        string `json:"kid"`
}

// NewKeyManager creates a new key manager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		userPublicKeys: make(map[string][]byte),
		groupKeys:      make(map[string]*GroupKey),
	}
}

// GenerateUserKeyPair generates a new X25519 keypair for a user
func GenerateUserKeyPair() (*UserKeyPair, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate public key: %w", err)
	}

	return &UserKeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// RegisterUserPublicKey stores a user's public key
func (km *KeyManager) RegisterUserPublicKey(userID string, publicKey []byte) error {
	if len(publicKey) != 32 {
		return fmt.Errorf("public key must be 32 bytes, got %d", len(publicKey))
	}
	km.userPublicKeys[userID] = publicKey
	return nil
}

// GetUserPublicKey retrieves a user's public key
func (km *KeyManager) GetUserPublicKey(userID string) ([]byte, error) {
	key, exists := km.userPublicKeys[userID]
	if !exists {
		return nil, fmt.Errorf("public key not found for user %s", userID)
	}
	return key, nil
}

// GenerateGroupKey creates a new group key for the guild
func (km *KeyManager) GenerateGroupKey() (*GroupKey, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate group key: %w", err)
	}

	now := time.Now().UTC()
	groupKey := &GroupKey{
		Key:       key,
		CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour), // 1 day expiry
	}

	// Store with date as key for easy lookup
	dateKey := now.Format("2006-01-02")
	km.groupKeys[dateKey] = groupKey

	return groupKey, nil
}

// GetCurrentGroupKey returns the current group key, creating one if needed
func (km *KeyManager) GetCurrentGroupKey() (*GroupKey, error) {
	dateKey := time.Now().UTC().Format("2006-01-02")
	
	if groupKey, exists := km.groupKeys[dateKey]; exists {
		return groupKey, nil
	}

	// Generate new group key for today
	return km.GenerateGroupKey()
}

// GetGroupKey returns a group key for a specific date
func (km *KeyManager) GetGroupKey(date time.Time) (*GroupKey, error) {
	dateKey := date.Format("2006-01-02")
	groupKey, exists := km.groupKeys[dateKey]
	if !exists {
		return nil, fmt.Errorf("group key not found for date %s", dateKey)
	}
	return groupKey, nil
}

// WrapGroupKeyForUser encrypts the group key for a specific user using X25519 ECDH
func (km *KeyManager) WrapGroupKeyForUser(userID string, groupKey *GroupKey) (*WrappedGroupKey, error) {
	userPublicKey, err := km.GetUserPublicKey(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user public key: %w", err)
	}

	// Generate ephemeral keypair for ECDH
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral public key: %w", err)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, userPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Use shared secret as ChaCha20-Poly1305 key
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt group key
	ciphertext := aead.Seal(nil, nonce, groupKey.Key, nil)

	// Combine ephemeral public key + nonce + ciphertext
	encryptedKey := make([]byte, 0, 32+len(nonce)+len(ciphertext))
	encryptedKey = append(encryptedKey, ephemeralPublic...)
	encryptedKey = append(encryptedKey, nonce...)
	encryptedKey = append(encryptedKey, ciphertext...)

	return &WrappedGroupKey{
		EncryptedKey: encryptedKey,
		Algorithm:    "xchacha20poly1305",
		KeyID:        groupKey.CreatedAt.Format("2006-01-02"),
	}, nil
}

// EncryptMessage encrypts a message using the group key
func EncryptMessage(groupKey *GroupKey, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(groupKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptMessage decrypts a message using the group key
func DecryptMessage(groupKey *GroupKey, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(groupKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:aead.NonceSize()]
	encrypted := ciphertext[aead.NonceSize():]

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// ToBase64 converts bytes to base64 string
func ToBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// FromBase64 converts base64 string to bytes
func FromBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
