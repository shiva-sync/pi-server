package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"shivasync/internal/crypto"
	"shivasync/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// Hub manages WebSocket connections and message routing
type Hub struct {
	logger      *zap.Logger
	keyManager  *crypto.KeyManager
	upgrader    websocket.Upgrader
	clients     map[string]*Client
	broadcast   chan *models.MessageEnvelope
	register    chan *Client
	unregister  chan *Client
	mutex       sync.RWMutex
	sequence    int64
}

// Client represents a WebSocket client connection
type Client struct {
	hub        *Hub
	conn       *websocket.Conn
	send       chan *models.MessageEnvelope
	info       *models.ClientConnection
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewHub creates a new WebSocket hub
func NewHub(logger *zap.Logger, keyManager *crypto.KeyManager) *Hub {
	return &Hub{
		logger:     logger,
		keyManager: keyManager,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				return true
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients:    make(map[string]*Client),
		broadcast:  make(chan *models.MessageEnvelope),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run starts the hub's main loop
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.registerClient(client)
		case client := <-h.unregister:
			h.unregisterClient(client)
		case envelope := <-h.broadcast:
			h.routeMessage(envelope)
		}
	}
}

// HandleWebSocket upgrades HTTP connection to WebSocket
func (h *Hub) HandleWebSocket(c *gin.Context) {
	// Extract user info from JWT context
	userID := c.GetString("user_id")
	username := c.GetString("username")
	guildID := c.GetString("guild_id")
	roles, _ := c.Get("roles")
	rolesList, _ := roles.([]string)

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	// Check if user already has a connection
	h.mutex.RLock()
	if existingClient, exists := h.clients[userID]; exists {
		h.mutex.RUnlock()
		// Close existing connection
		existingClient.cancel()
		h.logger.Info("Closing existing connection for user", zap.String("user_id", userID))
	} else {
		h.mutex.RUnlock()
	}

	// Upgrade connection
	conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("WebSocket upgrade failed", zap.Error(err))
		return
	}

	// Create client context
	ctx, cancel := context.WithCancel(context.Background())

	// Create client
	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan *models.MessageEnvelope, 64), // Buffer for backpressure
		info: &models.ClientConnection{
			UserID:    userID,
			Username:  username,
			GuildID:   guildID,
			Roles:     rolesList,
			ConnectAt: time.Now().UTC(),
			LastSeen:  time.Now().UTC(),
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Register client
	h.register <- client

	// Start client goroutines
	go client.writePump()
	go client.readPump()

	h.logger.Info("WebSocket connection established",
		zap.String("user_id", userID),
		zap.String("username", username))
}

// registerClient adds a client to the hub
func (h *Hub) registerClient(client *Client) {
	h.mutex.Lock()
	h.clients[client.info.UserID] = client
	h.mutex.Unlock()

	h.logger.Info("Client registered",
		zap.String("user_id", client.info.UserID),
		zap.Int("total_clients", len(h.clients)))

	// Send welcome message with current group key
	h.sendGroupKeyUpdate(client)

	// Broadcast presence update
	h.broadcastPresenceUpdate(client.info.UserID, "online")
}

// unregisterClient removes a client from the hub
func (h *Hub) unregisterClient(client *Client) {
	h.mutex.Lock()
	if _, exists := h.clients[client.info.UserID]; exists {
		delete(h.clients, client.info.UserID)
		close(client.send)
	}
	h.mutex.Unlock()

	// Close connection
	client.conn.Close()

	h.logger.Info("Client unregistered",
		zap.String("user_id", client.info.UserID),
		zap.Int("total_clients", len(h.clients)))

	// Broadcast presence update
	h.broadcastPresenceUpdate(client.info.UserID, "offline")
}

// sendGroupKeyUpdate sends the current group key to a client
func (h *Hub) sendGroupKeyUpdate(client *Client) {
	groupKey, err := h.keyManager.GetCurrentGroupKey()
	if err != nil {
		h.logger.Error("Failed to get current group key", zap.Error(err))
		return
	}

	wrappedKey, err := h.keyManager.WrapGroupKeyForUser(client.info.UserID, groupKey)
	if err != nil {
		h.logger.Error("Failed to wrap group key for user",
			zap.Error(err),
			zap.String("user_id", client.info.UserID))
		return
	}

	keyUpdate := &models.KeyUpdateMessage{
		EncryptedKey: crypto.ToBase64(wrappedKey.EncryptedKey),
		Algorithm:    wrappedKey.Algorithm,
		KeyID:        wrappedKey.KeyID,
	}

	// Create envelope (key updates are not encrypted themselves)
	envelope := models.NewMessageEnvelope(
		models.MessageTypeKeyUpdate,
		"server",
		models.GetDirectRoom(client.info.UserID),
		h.nextSequence(),
		"", // No ciphertext for key updates
	)

	// Marshal key update directly as the message
	keyUpdateData, err := json.Marshal(keyUpdate)
	if err != nil {
		h.logger.Error("Failed to marshal key update", zap.Error(err))
		return
	}
	envelope.Ciphertext = crypto.ToBase64(keyUpdateData)

	// Send to client
	select {
	case client.send <- envelope:
	default:
		h.logger.Warn("Client send buffer full, dropping key update",
			zap.String("user_id", client.info.UserID))
	}
}

// broadcastPresenceUpdate sends presence updates to all connected clients
func (h *Hub) broadcastPresenceUpdate(userID, status string) {
	presence := &models.PresenceMessage{
		Status: status,
	}

	h.broadcastToGroup(models.MessageTypePresence, userID, presence)
}

// broadcastToGroup sends a message to all clients in the group
func (h *Hub) broadcastToGroup(msgType models.MessageType, fromUserID string, payload interface{}) {
	// Get current group key
	groupKey, err := h.keyManager.GetCurrentGroupKey()
	if err != nil {
		h.logger.Error("Failed to get group key for broadcast", zap.Error(err))
		return
	}

	// Marshal payload
	payloadData, err := models.MarshalPayload(payload)
	if err != nil {
		h.logger.Error("Failed to marshal broadcast payload", zap.Error(err))
		return
	}

	// Encrypt payload
	ciphertext, err := crypto.EncryptMessage(groupKey, payloadData)
	if err != nil {
		h.logger.Error("Failed to encrypt broadcast message", zap.Error(err))
		return
	}

	// Create envelope
	envelope := models.NewMessageEnvelope(
		msgType,
		fromUserID,
		models.RoomTypeGroup,
		h.nextSequence(),
		crypto.ToBase64(ciphertext),
	)

	// Broadcast to all clients
	h.broadcast <- envelope
}

// routeMessage routes a message to appropriate recipients
func (h *Hub) routeMessage(envelope *models.MessageEnvelope) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if envelope.Room == models.RoomTypeGroup {
		// Broadcast to all clients in the same guild
		for _, client := range h.clients {
			if client.info.GuildID == h.getSenderGuildID(envelope.From) {
				select {
				case client.send <- envelope:
				default:
					h.logger.Warn("Client send buffer full, dropping message",
						zap.String("user_id", client.info.UserID))
				}
			}
		}
	} else if models.IsDirectRoom(envelope.Room) {
		// Direct message to specific user
		targetUserID := models.GetDirectRoomTarget(envelope.Room)
		if client, exists := h.clients[targetUserID]; exists {
			select {
			case client.send <- envelope:
			default:
				h.logger.Warn("Client send buffer full, dropping direct message",
					zap.String("target_user_id", targetUserID))
			}
		}
	}
}

// getSenderGuildID gets the guild ID for a sender (simplified - assumes same guild)
func (h *Hub) getSenderGuildID(senderUserID string) string {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	
	if client, exists := h.clients[senderUserID]; exists {
		return client.info.GuildID
	}
	return ""
}

// nextSequence returns the next sequence number
func (h *Hub) nextSequence() int64 {
	h.sequence++
	return h.sequence
}

// GetConnectedUsers returns a list of currently connected users
func (h *Hub) GetConnectedUsers() []*models.ClientConnection {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	users := make([]*models.ClientConnection, 0, len(h.clients))
	for _, client := range h.clients {
		users = append(users, client.info)
	}
	return users
}
