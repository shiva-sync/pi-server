package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"shivasync/internal/auth"
	"shivasync/internal/config"
	"shivasync/internal/crypto"
	"shivasync/internal/models"
	"shivasync/internal/storage"
	"shivasync/internal/websocket"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Server represents the main server instance
type Server struct {
	config        *config.Config
	logger        *zap.Logger
	storage       *storage.S3Client
	oauthCfg      *oauth2.Config
	router        *gin.Engine
	jwtManager    *auth.JWTManager
	discordClient *auth.DiscordClient
	keyManager    *crypto.KeyManager
	wsHub         *websocket.Hub
}

// HealthResponse represents the health check response
type HealthResponse struct {
	OK bool `json:"ok"`
}

// ReadinessResponse represents the readiness check response
type ReadinessResponse struct {
	S3      bool `json:"s3"`
	Discord bool `json:"discord"`
}

// New creates a new server instance
func New(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	// Initialize S3 client
	s3Client, err := storage.NewS3Client(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 client: %w", err)
	}

	// Configure OAuth2
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.DiscordClientID,
		ClientSecret: cfg.DiscordClientSecret,
		RedirectURL:  cfg.DiscordRedirectURI,
		Scopes:       []string{"identify", "bot"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}

	// Set gin mode based on log level
	if cfg.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(cfg.JWTSigningKey)

	// Initialize Discord client
	discordClient := auth.NewDiscordClient(oauthCfg, cfg.DiscordBotToken)

	// Initialize crypto key manager
	keyManager := crypto.NewKeyManager()

	// Initialize WebSocket hub
	wsHub := websocket.NewHub(logger, keyManager)

	s := &Server{
		config:        cfg,
		logger:        logger,
		storage:       s3Client,
		oauthCfg:      oauthCfg,
		router:        gin.New(),
		jwtManager:    jwtManager,
		discordClient: discordClient,
		keyManager:    keyManager,
		wsHub:         wsHub,
	}

	// Start WebSocket hub
	go wsHub.Run()

	s.setupRoutes()
	return s, nil
}

// Handler returns the HTTP handler
func (s *Server) Handler() http.Handler {
	return s.router
}

// setupRoutes configures all the routes
func (s *Server) setupRoutes() {
	// Add middleware
	s.router.Use(gin.Recovery())
	s.router.Use(s.loggingMiddleware())
	s.router.Use(s.corsMiddleware())

	// Health endpoints
	s.router.GET("/healthz", s.handleHealth)
	s.router.HEAD("/healthz", s.handleHealth)
	s.router.GET("/readyz", s.handleReadiness)
	s.router.HEAD("/readyz", s.handleReadiness)

	// OAuth endpoints (Stage 2)
	oauth := s.router.Group("/oauth")
	{
		oauth.GET("/login", s.handleOAuthLogin)
		oauth.GET("/callback", s.handleOAuthCallback)
	}

	// Auth endpoints (Stage 2)
	auth := s.router.Group("/auth")
	{
		auth.POST("/refresh", s.handleAuthRefresh)
	}

	// API v1 endpoints
	v1 := s.router.Group("/v1")
	{
		// Objects endpoints (Stage 3)
		objects := v1.Group("/objects")
		{
			objects.GET("/exists/:sha256", s.requireAuth(), s.handleObjectExists)
			objects.POST("/presign-put", s.requireAuth(), s.handlePresignPut)
			objects.POST("/presign-get", s.requireAuth(), s.handlePresignGet)
			objects.PUT("/metadata/:sha256", s.requireAuth(), s.handleObjectMetadata)
		}

		// WebSocket endpoint (Stage 4)
		v1.GET("/ws", s.requireAuth(), s.handleWebSocket)

		// Crypto endpoints (Stage 4)
		crypto := v1.Group("/crypto")
		crypto.Use(s.requireAuth())
		{
			crypto.GET("/group-key", s.handleCryptoGroupKey)
			crypto.GET("/group-key/:date", s.handleCryptoGroupKeyByDate)
			crypto.POST("/register-key", s.handleCryptoRegisterKey)
		}

		// Admin endpoints (Stage 6)
		admin := v1.Group("/admin")
		admin.Use(s.requireAdminAuth())
		{
			admin.POST("/denylist", s.handleAdminDenylistAdd)
			admin.DELETE("/denylist/:sha256", s.handleAdminDenylistRemove)
			admin.GET("/denylist", s.handleAdminDenylistList)
			admin.GET("/users", s.handleAdminUsersList)
			admin.DELETE("/users/:userID", s.handleAdminUsersRevoke)
			admin.GET("/stats", s.handleAdminStats)
		}
	}

	// Admin UI endpoints (Stage 7 - Stretch Goal)
	if s.config.AdminUIEnabled {
		adminUI := s.router.Group("/admin")
		{
			adminUI.POST("/login", s.handleAdminLogin)
			adminUI.POST("/logout", s.handleAdminLogout)
			adminUI.GET("/session", s.handleAdminSession)
			adminUI.Static("/", "./web/dist")
		}
	}
}

// Health check endpoint
func (s *Server) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{OK: true})
}

// Readiness check endpoint
func (s *Server) handleReadiness(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	response := ReadinessResponse{
		S3:      true,
		Discord: true,
	}

	// Check S3 connection
	if err := s.storage.HeadBucket(ctx); err != nil {
		s.logger.Warn("S3 readiness check failed", zap.Error(err))
		response.S3 = false
	}

	// Check Discord API (basic connectivity test)
	// Create a test OAuth config just to validate credentials
	testToken := &oauth2.Token{AccessToken: "invalid"} // This will fail, which is expected
	if err := s.discordClient.ValidateDiscordToken(ctx, testToken); err == nil {
		// If this succeeds with an invalid token, something is wrong
		s.logger.Warn("Discord readiness check: unexpected success with invalid token")
		response.Discord = false
	} else {
		// We expect this to fail - if it fails with an auth error, Discord API is reachable
		response.Discord = true
	}

	if !response.S3 || !response.Discord {
		c.JSON(http.StatusServiceUnavailable, response)
		return
	}

	c.JSON(http.StatusOK, response)
}

// OAuth and Auth endpoint implementations

type AuthRefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type AuthResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// OAuth login endpoint - redirects to Discord
func (s *Server) handleOAuthLogin(c *gin.Context) {
	// Generate random state for CSRF protection
	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		s.logger.Error("Failed to generate OAuth state", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	stateString := base64.URLEncoding.EncodeToString(state)

	// Store state in session/cookie for validation (simplified for now)
	c.SetCookie("oauth_state", stateString, 600, "/", "", true, true)

	// Redirect to Discord with bot permissions
	url := s.oauthCfg.AuthCodeURL(stateString, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("permissions", "67108864"))
	c.Redirect(http.StatusFound, url)
}

// OAuth callback endpoint - handles Discord callback
func (s *Server) handleOAuthCallback(c *gin.Context) {
	// Validate state parameter
	state := c.Query("state")
	storedState, err := c.Cookie("oauth_state")
	if err != nil || state != storedState {
		s.logger.Warn("Invalid OAuth state", zap.String("provided", state), zap.String("stored", storedState))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state parameter"})
		return
	}

	// Clear the state cookie
	c.SetCookie("oauth_state", "", -1, "/", "", true, true)

	// Get authorization code
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing authorization code"})
		return
	}

	// Exchange code for token
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	token, err := s.oauthCfg.Exchange(ctx, code)
	if err != nil {
		s.logger.Error("Failed to exchange OAuth code", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to exchange authorization code"})
		return
	}

	// Get user information
	user, err := s.discordClient.GetUser(ctx, token)
	if err != nil {
		s.logger.Error("Failed to get Discord user", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to get user information"})
		return
	}

	// Check if user has required role in guild
	s.logger.Info("Checking user roles with bot token",
		zap.String("user_id", user.ID),
		zap.String("guild_id", s.config.DiscordGuildID),
		zap.String("required_role_id", s.config.DiscordRequiredRoleID),
		zap.Bool("bot_token_set", s.config.DiscordBotToken != ""))

	hasRole, roles, err := s.discordClient.HasRoleWithBot(ctx, s.config.DiscordGuildID, user.ID, s.config.DiscordRequiredRoleID)
	if err != nil {
		s.logger.Error("Failed to check user roles", zap.Error(err), zap.String("user_id", user.ID))
		c.JSON(http.StatusForbidden, gin.H{"error": "failed to verify guild membership"})
		return
	}

	if !hasRole {
		s.logger.Warn("User lacks required role", zap.String("user_id", user.ID), zap.String("username", user.GetDisplayName()))
		c.JSON(http.StatusForbidden, gin.H{"error": "missing required Discord role"})
		return
	}

	// Encrypt and store refresh token
	encryptedRefreshToken, err := s.jwtManager.EncryptRefreshToken(token.RefreshToken)
	if err != nil {
		s.logger.Error("Failed to encrypt refresh token", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Generate JWT token
	jwtToken, err := s.jwtManager.GenerateToken(user.ID, s.config.DiscordGuildID, user.GetDisplayName(), roles)
	if err != nil {
		s.logger.Error("Failed to generate JWT", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	s.logger.Info("User authenticated successfully",
		zap.String("user_id", user.ID),
		zap.String("username", user.GetDisplayName()),
		zap.Int("roles_count", len(roles)))

	// TODO: Store encrypted refresh token in database for user
	// For now, we'll return it as a cookie (not ideal for production)
	c.SetCookie("refresh_token", encryptedRefreshToken, 86400*7, "/", "", true, true) // 7 days

	// Return JWT token
	c.JSON(http.StatusOK, AuthResponse{
		AccessToken: jwtToken,
		ExpiresIn:   1800, // 30 minutes
	})
}

// Auth refresh endpoint - exchanges refresh token for new access token
func (s *Server) handleAuthRefresh(c *gin.Context) {
	var req AuthRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Decrypt refresh token
	refreshToken, err := s.jwtManager.DecryptRefreshToken(req.RefreshToken)
	if err != nil {
		s.logger.Error("Failed to decrypt refresh token", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid refresh token"})
		return
	}

	// Create token source with refresh token
	tokenSource := s.oauthCfg.TokenSource(c.Request.Context(), &oauth2.Token{
		RefreshToken: refreshToken,
	})

	// Get new token
	newToken, err := tokenSource.Token()
	if err != nil {
		s.logger.Error("Failed to refresh Discord token", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to refresh token"})
		return
	}

	// Get user information with new token
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	user, err := s.discordClient.GetUser(ctx, newToken)
	if err != nil {
		s.logger.Error("Failed to get Discord user on refresh", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "failed to verify user"})
		return
	}

	// Check roles again
	hasRole, roles, err := s.discordClient.HasRoleWithBot(ctx, s.config.DiscordGuildID, user.ID, s.config.DiscordRequiredRoleID)
	if err != nil {
		s.logger.Error("Failed to check user roles on refresh", zap.Error(err))
		c.JSON(http.StatusForbidden, gin.H{"error": "failed to verify guild membership"})
		return
	}

	if !hasRole {
		s.logger.Warn("User lost required role", zap.String("user_id", user.ID))
		c.JSON(http.StatusForbidden, gin.H{"error": "missing required Discord role"})
		return
	}

	// Generate new JWT
	jwtToken, err := s.jwtManager.GenerateToken(user.ID, s.config.DiscordGuildID, user.GetDisplayName(), roles)
	if err != nil {
		s.logger.Error("Failed to generate JWT on refresh", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Return new JWT token
	c.JSON(http.StatusOK, AuthResponse{
		AccessToken: jwtToken,
		ExpiresIn:   1800, // 30 minutes
	})
}

// Object existence check endpoint
func (s *Server) handleObjectExists(c *gin.Context) {
	sha256Hash := c.Param("sha256")

	// Validate SHA256 format
	if err := models.ValidateSHA256(sha256Hash); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if object exists in S3
	key := storage.ObjectKey(sha256Hash)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	_, err := s.storage.HeadObject(ctx, key)
	if err != nil {
		// Object doesn't exist
		c.JSON(http.StatusNotFound, gin.H{"error": "object not found"})
		return
	}

	// Object exists
	c.JSON(http.StatusOK, gin.H{"exists": true})
}

// Presigned PUT endpoint for uploads
func (s *Server) handlePresignPut(c *gin.Context) {
	var req models.PresignPutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "detail": err.Error()})
		return
	}

	// Validate SHA256 format
	if err := models.ValidateSHA256(req.SHA256); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if object already exists (prevent hash collisions)
	key := storage.ObjectKey(req.SHA256)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if _, err := s.storage.HeadObject(ctx, key); err == nil {
		// Object already exists - this could be a hash collision or duplicate upload
		c.JSON(http.StatusConflict, gin.H{"error": "object with this hash already exists"})
		return
	}

	// Set content type if not provided
	contentType := req.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Create metadata for S3 object
	metadata := map[string]string{
		"sha256":       req.SHA256,
		"size":         fmt.Sprintf("%d", req.Size),
		"content-type": contentType,
	}

	// Generate presigned PUT URL
	url, headers, err := s.storage.PresignPutObject(ctx, key, metadata)
	if err != nil {
		s.logger.Error("Failed to create presigned PUT URL", zap.Error(err), zap.String("sha256", req.SHA256))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create presigned URL"})
		return
	}

	response := models.PresignPutResponse{
		URL:       url,
		Headers:   headers,
		ExpiresIn: 600, // 10 minutes
	}

	s.logger.Info("Generated presigned PUT URL",
		zap.String("sha256", req.SHA256),
		zap.Int64("size", req.Size),
		zap.String("user_id", c.GetString("user_id")))

	c.JSON(http.StatusOK, response)
}

// Presigned GET endpoint for downloads
func (s *Server) handlePresignGet(c *gin.Context) {
	var req models.PresignGetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "detail": err.Error()})
		return
	}

	// Validate SHA256 format
	if err := models.ValidateSHA256(req.SHA256); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if object exists
	key := storage.ObjectKey(req.SHA256)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	if _, err := s.storage.HeadObject(ctx, key); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "object not found"})
		return
	}

	// Generate presigned GET URL
	url, err := s.storage.PresignGetObject(ctx, key)
	if err != nil {
		s.logger.Error("Failed to create presigned GET URL", zap.Error(err), zap.String("sha256", req.SHA256))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create presigned URL"})
		return
	}

	response := models.PresignGetResponse{
		URL:       url,
		ExpiresIn: 600, // 10 minutes
	}

	s.logger.Info("Generated presigned GET URL",
		zap.String("sha256", req.SHA256),
		zap.String("user_id", c.GetString("user_id")))

	c.JSON(http.StatusOK, response)
}

// Object metadata endpoint
func (s *Server) handleObjectMetadata(c *gin.Context) {
	sha256Hash := c.Param("sha256")

	// Validate SHA256 format
	if err := models.ValidateSHA256(sha256Hash); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if c.Request.Method == "PUT" {
		// Store metadata
		var meta models.ObjectMeta
		if err := c.ShouldBindJSON(&meta); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "detail": err.Error()})
			return
		}

		// Set created_at if not provided
		if meta.CreatedAt.IsZero() {
			meta.CreatedAt = time.Now().UTC()
		}

		// Set uploader from JWT claims
		userID := c.GetString("user_id")
		username := c.GetString("username")
		if userID != "" {
			meta.Uploader = fmt.Sprintf("%s (%s)", username, userID)
		}

		// Store metadata in S3
		metaKey := storage.MetadataKey(sha256Hash)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()

		if err := s.storage.PutObjectMetadata(ctx, metaKey, meta); err != nil {
			s.logger.Error("Failed to store object metadata", zap.Error(err), zap.String("sha256", sha256Hash))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store metadata"})
			return
		}

		s.logger.Info("Stored object metadata",
			zap.String("sha256", sha256Hash),
			zap.String("uploader", meta.Uploader),
			zap.String("licence", meta.Licence))

		c.JSON(http.StatusNoContent, nil)
	} else {
		// Retrieve metadata
		metaKey := storage.MetadataKey(sha256Hash)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
		defer cancel()

		metadata, err := s.storage.GetObjectMetadata(ctx, metaKey)
		if err != nil {
			s.logger.Debug("Failed to retrieve object metadata", zap.Error(err), zap.String("sha256", sha256Hash))
			c.JSON(http.StatusNotFound, gin.H{"error": "metadata not found"})
			return
		}

		c.JSON(http.StatusOK, metadata)
	}
}

// WebSocket handler
func (s *Server) handleWebSocket(c *gin.Context) {
	s.wsHub.HandleWebSocket(c)
}

// Crypto endpoints

// RegisterKeyRequest represents a user public key registration
type RegisterKeyRequest struct {
	PublicKey string `json:"public_key" binding:"required"`
}

// GroupKeyResponse represents a wrapped group key response
type GroupKeyResponse struct {
	EncryptedKey string `json:"encrypted_key"`
	Algorithm    string `json:"algorithm"`
	KeyID        string `json:"key_id"`
	ExpiresAt    string `json:"expires_at"`
}

// Register user public key
func (s *Server) handleCryptoRegisterKey(c *gin.Context) {
	var req RegisterKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body", "detail": err.Error()})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	// Decode public key
	publicKey, err := crypto.FromBase64(req.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public key format"})
		return
	}

	// Register public key
	if err := s.keyManager.RegisterUserPublicKey(userID, publicKey); err != nil {
		s.logger.Error("Failed to register user public key", zap.Error(err), zap.String("user_id", userID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register public key"})
		return
	}

	s.logger.Info("User public key registered", zap.String("user_id", userID))
	c.JSON(http.StatusOK, gin.H{"status": "registered"})
}

// Get current group key wrapped for requesting user
func (s *Server) handleCryptoGroupKey(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	// Get current group key
	groupKey, err := s.keyManager.GetCurrentGroupKey()
	if err != nil {
		s.logger.Error("Failed to get current group key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get group key"})
		return
	}

	// Wrap for user
	wrappedKey, err := s.keyManager.WrapGroupKeyForUser(userID, groupKey)
	if err != nil {
		s.logger.Error("Failed to wrap group key for user", zap.Error(err), zap.String("user_id", userID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to wrap group key"})
		return
	}

	response := GroupKeyResponse{
		EncryptedKey: crypto.ToBase64(wrappedKey.EncryptedKey),
		Algorithm:    wrappedKey.Algorithm,
		KeyID:        wrappedKey.KeyID,
		ExpiresAt:    groupKey.ExpiresAt.Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

// Get historical group key by date
func (s *Server) handleCryptoGroupKeyByDate(c *gin.Context) {
	dateStr := c.Param("date")
	userID := c.GetString("user_id")

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
		return
	}

	// Parse date
	date, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid date format, use YYYY-MM-DD"})
		return
	}

	// Check if date is not too old (max 7 days as per spec)
	if time.Since(date) > 7*24*time.Hour {
		c.JSON(http.StatusNotFound, gin.H{"error": "group key too old"})
		return
	}

	// Get group key for date
	groupKey, err := s.keyManager.GetGroupKey(date)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group key not found for date"})
		return
	}

	// Wrap for user
	wrappedKey, err := s.keyManager.WrapGroupKeyForUser(userID, groupKey)
	if err != nil {
		s.logger.Error("Failed to wrap historical group key for user", zap.Error(err), zap.String("user_id", userID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to wrap group key"})
		return
	}

	response := GroupKeyResponse{
		EncryptedKey: crypto.ToBase64(wrappedKey.EncryptedKey),
		Algorithm:    wrappedKey.Algorithm,
		KeyID:        wrappedKey.KeyID,
		ExpiresAt:    groupKey.ExpiresAt.Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

func (s *Server) handleAdminDenylistAdd(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminDenylistRemove(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminDenylistList(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminUsersList(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminUsersRevoke(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminStats(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminLogin(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminLogout(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

func (s *Server) handleAdminSession(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
}

// Middleware
func (s *Server) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		s.logger.Info("HTTP request",
			zap.String("method", param.Method),
			zap.String("path", param.Path),
			zap.Int("status", param.StatusCode),
			zap.Duration("latency", param.Latency),
			zap.String("client_ip", param.ClientIP),
		)
		return ""
	})
}

func (s *Server) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if s.config.AllowOrigin != "" && origin == s.config.AllowOrigin {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

func (s *Server) requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		// Check Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		// Validate JWT token
		claims, err := s.jwtManager.ValidateToken(parts[1])
		if err != nil {
			s.logger.Debug("JWT validation failed", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Store claims in context for use by handlers
		c.Set("user_id", claims.UserID)
		c.Set("guild_id", claims.GuildID)
		c.Set("roles", claims.Roles)
		c.Set("username", claims.Username)

		c.Next()
	}
}

func (s *Server) requireAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement admin authentication
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
		c.Abort()
	}
}
