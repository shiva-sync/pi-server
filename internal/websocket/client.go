package websocket

import (
	"encoding/json"
	"time"

	"shivasync/internal/models"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512 * 1024 // 512KB
)

// readPump pumps messages from the websocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Read message
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.logger.Error("WebSocket read error", zap.Error(err))
			}
			break
		}

		// Update last seen
		c.info.LastSeen = time.Now().UTC()

		// Parse message envelope
		var envelope models.MessageEnvelope
		if err := json.Unmarshal(message, &envelope); err != nil {
			c.hub.logger.Warn("Invalid message format",
				zap.Error(err),
				zap.String("user_id", c.info.UserID))
			continue
		}

		// Validate message
		if err := c.validateMessage(&envelope); err != nil {
			c.hub.logger.Warn("Message validation failed",
				zap.Error(err),
				zap.String("user_id", c.info.UserID))
			continue
		}

		// Set sender
		envelope.From = c.info.UserID
		envelope.Timestamp = time.Now().UTC()
		envelope.Sequence = c.hub.nextSequence()

		c.hub.logger.Debug("Received message",
			zap.String("user_id", c.info.UserID),
			zap.String("type", string(envelope.Type)),
			zap.String("room", envelope.Room))

		// Route message
		c.hub.broadcast <- &envelope
	}
}

// writePump pumps messages from the hub to the websocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		case envelope, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Channel closed
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Send message
			if err := c.conn.WriteJSON(envelope); err != nil {
				c.hub.logger.Error("WebSocket write error",
					zap.Error(err),
					zap.String("user_id", c.info.UserID))
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// validateMessage validates incoming message envelope
func (c *Client) validateMessage(envelope *models.MessageEnvelope) error {
	// Basic validation
	if envelope.Version != 1 {
		return &ValidationError{"unsupported_version", "Message version must be 1"}
	}

	// Validate message type
	switch envelope.Type {
	case models.MessageTypeDesign, models.MessageTypeManifest, models.MessageTypePresence:
		// Valid message types from clients
	default:
		return &ValidationError{"invalid_type", "Invalid message type"}
	}

	// Validate room
	if envelope.Room != models.RoomTypeGroup && !models.IsDirectRoom(envelope.Room) {
		return &ValidationError{"invalid_room", "Invalid room format"}
	}

	// Validate direct message target
	if models.IsDirectRoom(envelope.Room) {
		targetUserID := models.GetDirectRoomTarget(envelope.Room)
		if targetUserID == "" {
			return &ValidationError{"invalid_direct_target", "Invalid direct message target"}
		}
		
		// Check if target user is connected
		c.hub.mutex.RLock()
		_, exists := c.hub.clients[targetUserID]
		c.hub.mutex.RUnlock()
		
		if !exists {
			return &ValidationError{"target_offline", "Target user is not connected"}
		}
	}

	// Validate ciphertext presence
	if envelope.Ciphertext == "" {
		return &ValidationError{"missing_ciphertext", "Message must contain encrypted payload"}
	}

	return nil
}

// ValidationError represents a message validation error
type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// SendError sends an error message to the client
func (c *Client) SendError(code, message, detail string) {
	errorMsg := &models.ErrorMessage{
		Code:    code,
		Message: message,
		Detail:  detail,
	}

	envelope := models.NewMessageEnvelope(
		models.MessageTypeError,
		"server",
		models.GetDirectRoom(c.info.UserID),
		c.hub.nextSequence(),
		"", // Error messages are not encrypted
	)

	// Marshal error directly
	errorData, err := json.Marshal(errorMsg)
	if err != nil {
		c.hub.logger.Error("Failed to marshal error message", zap.Error(err))
		return
	}
	envelope.Ciphertext = string(errorData)

	select {
	case c.send <- envelope:
	default:
		c.hub.logger.Warn("Could not send error message, client buffer full",
			zap.String("user_id", c.info.UserID))
	}
}
