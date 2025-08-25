package models

import (
	"encoding/json"
	"time"
)

// MessageType represents the different types of messages
type MessageType string

const (
	MessageTypeDesign    MessageType = "design"
	MessageTypeManifest  MessageType = "manifest"
	MessageTypePresence  MessageType = "presence"
	MessageTypeKeyUpdate MessageType = "keyupdate"
	MessageTypeError     MessageType = "error"
)

// MessageEnvelope represents the outer message structure sent over WebSocket
type MessageEnvelope struct {
	Version    int         `json:"v"`
	Type       MessageType `json:"type"`
	Nonce      string      `json:"nonce"`
	From       string      `json:"from"`
	Room       string      `json:"room"`
	Sequence   int64       `json:"seq"`
	Timestamp  time.Time   `json:"timestamp"`
	Ciphertext string      `json:"ciphertext"` // Base64 encoded encrypted payload
}

// Room types
const (
	RoomTypeGroup  = "group"
	RoomTypeDirect = "direct:" // followed by userID
)

// Plaintext message payloads (before encryption)

// DesignMessage represents a Glamourer design share
type DesignMessage struct {
	CharacterID string   `json:"character_id"`
	Glamourer   string   `json:"glamourer"`
	AppliesTo   []string `json:"applies_to"` // ["self", "target", "nearby"]
}

// ManifestMessage represents a mod manifest
type ManifestMessage struct {
	CharacterID string         `json:"character_id"`
	Mods        []ManifestMod  `json:"mods"`
	Version     int            `json:"version"`
}

// ManifestMod represents a single mod file in a manifest
type ManifestMod struct {
	GamePath string `json:"game_path"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// PresenceMessage represents user presence status
type PresenceMessage struct {
	Status string `json:"status"` // "online" or "offline"
}

// KeyUpdateMessage represents a group key update
type KeyUpdateMessage struct {
	EncryptedKey string `json:"ek"`  // Base64 encoded wrapped group key
	Algorithm    string `json:"alg"` // "xchacha20poly1305"
	KeyID        string `json:"kid"` // Date string for key identification
}

// ErrorMessage represents an error response
type ErrorMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// WebSocket client connection info
type ClientConnection struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	GuildID   string    `json:"guild_id"`
	Roles     []string  `json:"roles"`
	ConnectAt time.Time `json:"connected_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// Helper functions for message creation

// NewMessageEnvelope creates a new message envelope
func NewMessageEnvelope(msgType MessageType, from, room string, seq int64, ciphertext string) *MessageEnvelope {
	return &MessageEnvelope{
		Version:    1,
		Type:       msgType,
		Nonce:      generateNonce(),
		From:       from,
		Room:       room,
		Sequence:   seq,
		Timestamp:  time.Now().UTC(),
		Ciphertext: ciphertext,
	}
}

// MarshalPayload marshals a payload to JSON
func MarshalPayload(payload interface{}) ([]byte, error) {
	return json.Marshal(payload)
}

// UnmarshalPayload unmarshals a JSON payload
func UnmarshalPayload(data []byte, payload interface{}) error {
	return json.Unmarshal(data, payload)
}

// GetDirectRoom returns the room name for direct messages to a user
func GetDirectRoom(userID string) string {
	return RoomTypeDirect + userID
}

// IsDirectRoom checks if a room is a direct message room
func IsDirectRoom(room string) bool {
	return len(room) > len(RoomTypeDirect) && room[:len(RoomTypeDirect)] == RoomTypeDirect
}

// GetDirectRoomTarget extracts the target userID from a direct room name
func GetDirectRoomTarget(room string) string {
	if !IsDirectRoom(room) {
		return ""
	}
	return room[len(RoomTypeDirect):]
}

// Simple nonce generation (for message ordering, not crypto)
func generateNonce() string {
	// In production, use a proper UUID library
	return time.Now().Format("20060102150405.000000")
}
