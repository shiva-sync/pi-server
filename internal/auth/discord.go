package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// DiscordUser represents a Discord user
type DiscordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	GlobalName    string `json:"global_name"`
}

// DiscordGuildMember represents a Discord guild member
type DiscordGuildMember struct {
	User  *DiscordUser `json:"user"`
	Roles []string     `json:"roles"`
}

// DiscordClient handles Discord API interactions
type DiscordClient struct {
	oauthConfig *oauth2.Config
	httpClient  *http.Client
}

// NewDiscordClient creates a new Discord client
func NewDiscordClient(oauthConfig *oauth2.Config) *DiscordClient {
	return &DiscordClient{
		oauthConfig: oauthConfig,
		httpClient:  &http.Client{},
	}
}

// GetUser fetches user information from Discord
func (d *DiscordClient) GetUser(ctx context.Context, token *oauth2.Token) (*DiscordUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Discord API error: %d %s", resp.StatusCode, string(body))
	}

	var user DiscordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

// GetGuildMember fetches guild member information from Discord
func (d *DiscordClient) GetGuildMember(ctx context.Context, token *oauth2.Token, guildID, userID string) (*DiscordGuildMember, error) {
	url := fmt.Sprintf("https://discord.com/api/guilds/%s/members/%s", guildID, userID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user not found in guild")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Discord API error: %d %s", resp.StatusCode, string(body))
	}

	var member DiscordGuildMember
	if err := json.NewDecoder(resp.Body).Decode(&member); err != nil {
		return nil, err
	}

	return &member, nil
}

// HasRole checks if a user has a specific role in a guild
func (d *DiscordClient) HasRole(ctx context.Context, token *oauth2.Token, guildID, userID, requiredRoleID string) (bool, []string, error) {
	member, err := d.GetGuildMember(ctx, token, guildID, userID)
	if err != nil {
		return false, nil, err
	}

	// Check if user has the required role
	hasRole := false
	for _, roleID := range member.Roles {
		if roleID == requiredRoleID {
			hasRole = true
			break
		}
	}

	return hasRole, member.Roles, nil
}

// ValidateDiscordToken validates a Discord token by making a test API call
func (d *DiscordClient) ValidateDiscordToken(ctx context.Context, token *oauth2.Token) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid Discord token")
	}

	return nil
}

// GetDisplayName returns a user's display name (global_name or username)
func (u *DiscordUser) GetDisplayName() string {
	if u.GlobalName != "" {
		return u.GlobalName
	}
	if u.Discriminator != "0" {
		return fmt.Sprintf("%s#%s", u.Username, u.Discriminator)
	}
	return u.Username
}
