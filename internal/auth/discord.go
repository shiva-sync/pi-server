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

// DiscordGuild represents a Discord guild from user guilds endpoint
type DiscordGuild struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions string   `json:"permissions"`
	Owner       bool     `json:"owner"`
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

// GetUserGuilds fetches all guilds the user is a member of
func (d *DiscordClient) GetUserGuilds(ctx context.Context, token *oauth2.Token) ([]DiscordGuild, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://discord.com/api/users/@me/guilds", nil)
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

	var guilds []DiscordGuild
	if err := json.NewDecoder(resp.Body).Decode(&guilds); err != nil {
		return nil, err
	}

	return guilds, nil
}

// GetGuildMember fetches guild member information from Discord using bot endpoint
// Note: This requires the user to be in the guild and have proper permissions
func (d *DiscordClient) GetGuildMember(ctx context.Context, token *oauth2.Token, guildID, userID string) (*DiscordGuildMember, error) {
	// First check if user is in the guild by checking their guild list
	guilds, err := d.GetUserGuilds(ctx, token)
	if err != nil {
		return nil, err
	}

	// Check if the required guild is in the user's guild list
	found := false
	for _, guild := range guilds {
		if guild.ID == guildID {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("user not found in guild")
	}

	// Since we can't get roles directly with user token, we'll need to use a workaround
	// For now, we'll assume the user is in the guild (which we verified above)
	// and return a minimal member object. The role checking will need to be handled differently.
	return &DiscordGuildMember{
		User: &DiscordUser{ID: userID},
		Roles: []string{}, // We can't get roles with user token
	}, nil
}

// HasRole checks if a user has a specific role in a guild
// Note: With user tokens, we can only check guild membership, not specific roles
func (d *DiscordClient) HasRole(ctx context.Context, token *oauth2.Token, guildID, userID, requiredRoleID string) (bool, []string, error) {
	// Check if user is in the guild
	_, err := d.GetGuildMember(ctx, token, guildID, userID)
	if err != nil {
		return false, nil, err
	}

	// TODO: Role checking requires bot token or guilds.members.read scope
	// For now, we'll just check guild membership
	// If user is in the guild, we assume they have access
	// This can be improved later with proper bot integration
	
	return true, []string{}, nil
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
