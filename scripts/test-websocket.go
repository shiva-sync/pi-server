package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// Test JWT claims
type TestClaims struct {
	UserID   string   `json:"sub"`
	GuildID  string   `json:"guild_id"`
	Roles    []string `json:"roles"`
	Username string   `json:"username"`
	jwt.RegisteredClaims
}

// Message structures
type MessageEnvelope struct {
	Version    int    `json:"v"`
	Type       string `json:"type"`
	Nonce      string `json:"nonce"`
	From       string `json:"from"`
	Room       string `json:"room"`
	Sequence   int64  `json:"seq"`
	Timestamp  string `json:"timestamp"`
	Ciphertext string `json:"ciphertext"`
}

type PresenceMessage struct {
	Status string `json:"status"`
}

type DesignMessage struct {
	CharacterID string   `json:"character_id"`
	Glamourer   string   `json:"glamourer"`
	AppliesTo   []string `json:"applies_to"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run test-websocket.go <user1|user2> <message>")
		fmt.Println("Examples:")
		fmt.Println("  go run test-websocket.go user1 presence")
		fmt.Println("  go run test-websocket.go user2 design")
		os.Exit(1)
	}

	userType := os.Args[1]
	messageType := os.Args[2]

	// Generate different users for testing
	var userID, username string
	switch userType {
	case "user1":
		userID = "test-user-1"
		username = "TestUser1"
	case "user2":
		userID = "test-user-2"
		username = "TestUser2"
	default:
		log.Fatal("User must be user1 or user2")
	}

	// Generate JWT token
	token, err := generateToken(userID, username)
	if err != nil {
		log.Fatal("Failed to generate token:", err)
	}

	// Connect to WebSocket
	u := url.URL{Scheme: "ws", Host: "localhost:8080", Path: "/v1/ws"}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	c, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer c.Close()

	fmt.Printf("Connected as %s\n", username)

	// Handle interrupt
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	done := make(chan struct{})

	// Read messages
	go func() {
		defer close(done)
		for {
			var envelope MessageEnvelope
			err := c.ReadJSON(&envelope)
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					return
				}
				log.Println("read:", err)
				return
			}
			fmt.Printf("Received: %s message from %s to %s\n", envelope.Type, envelope.From, envelope.Room)
			if envelope.Type == "keyupdate" {
				fmt.Printf("  Key update received from server\n")
			}
		}
	}()

	// Send test message
	time.Sleep(1 * time.Second) // Wait for connection to stabilize

	switch messageType {
	case "presence":
		sendPresenceMessage(c, userID, "online")
	case "design":
		sendDesignMessage(c, userID, "Test Character", "test-glamourer-data")
	default:
		fmt.Printf("Unknown message type: %s\n", messageType)
	}

	// Keep connection alive and listen for messages
	fmt.Println("Listening for messages... Press Ctrl+C to exit")
	for {
		select {
		case <-done:
			return
		case <-interrupt:
			log.Println("interrupt")
			// Cleanly close the connection
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func generateToken(userID, username string) (string, error) {
	signingKey := "K0ufhnJcbyCrNqlWfZifbrWzoLDzbcVv5sn1uoRjkc0="
	key, err := base64.StdEncoding.DecodeString(signingKey)
	if err != nil {
		return "", err
	}

	claims := TestClaims{
		UserID:   userID,
		GuildID:  "221305060884348930",
		Roles:    []string{"1409555023041663006"},
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(key)
}

func sendPresenceMessage(c *websocket.Conn, userID, status string) {
	presence := PresenceMessage{Status: status}
	payload, _ := json.Marshal(presence)

	envelope := MessageEnvelope{
		Version:    1,
		Type:       "presence",
		Nonce:      fmt.Sprintf("%d", time.Now().UnixNano()),
		Room:       "group",
		Ciphertext: base64.StdEncoding.EncodeToString(payload), // For testing, we'll send unencrypted
	}

	err := c.WriteJSON(envelope)
	if err != nil {
		log.Println("write error:", err)
		return
	}
	fmt.Printf("Sent presence message: %s\n", status)
}

func sendDesignMessage(c *websocket.Conn, userID, characterID, glamourer string) {
	design := DesignMessage{
		CharacterID: characterID,
		Glamourer:   glamourer,
		AppliesTo:   []string{"target"},
	}
	payload, _ := json.Marshal(design)

	envelope := MessageEnvelope{
		Version:    1,
		Type:       "design",
		Nonce:      fmt.Sprintf("%d", time.Now().UnixNano()),
		Room:       "group",
		Ciphertext: base64.StdEncoding.EncodeToString(payload), // For testing, we'll send unencrypted
	}

	err := c.WriteJSON(envelope)
	if err != nil {
		log.Println("write error:", err)
		return
	}
	fmt.Printf("Sent design message for character: %s\n", characterID)
}
