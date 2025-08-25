package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Test JWT claims
type TestClaims struct {
	UserID   string   `json:"sub"`
	GuildID  string   `json:"guild_id"`
	Roles    []string `json:"roles"`
	Username string   `json:"username"`
	jwt.RegisteredClaims
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test-client.go <command> [args...]")
		fmt.Println("Commands:")
		fmt.Println("  token                 - Generate test JWT token")
		fmt.Println("  exists <sha256>       - Check if object exists")
		fmt.Println("  presign-put <sha256> <size> - Get presigned PUT URL")
		fmt.Println("  presign-get <sha256>  - Get presigned GET URL")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "token":
		generateToken()
	case "exists":
		if len(os.Args) < 3 {
			log.Fatal("Usage: test-client exists <sha256>")
		}
		checkExists(os.Args[2])
	case "presign-put":
		if len(os.Args) < 4 {
			log.Fatal("Usage: test-client presign-put <sha256> <size>")
		}
		presignPut(os.Args[2], os.Args[3])
	case "presign-get":
		if len(os.Args) < 3 {
			log.Fatal("Usage: test-client presign-get <sha256>")
		}
		presignGet(os.Args[2])
	default:
		log.Fatal("Unknown command:", command)
	}
}

func generateToken() {
	// Use the same JWT signing key from test.env
	signingKey := "K0ufhnJcbyCrNqlWfZifbrWzoLDzbcVv5sn1uoRjkc0="
	
	// Decode base64 key
	key, err := base64.StdEncoding.DecodeString(signingKey)
	if err != nil {
		log.Fatal("Failed to decode signing key:", err)
	}
	
	claims := TestClaims{
		UserID:   "test-user-123",
		GuildID:  "221305060884348930",
		Roles:    []string{"1409555023041663006"},
		Username: "TestUser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		log.Fatal("Failed to sign token:", err)
	}

	fmt.Println("Test JWT Token:")
	fmt.Println(tokenString)
	fmt.Println()
	fmt.Println("Use with: curl -H \"Authorization: Bearer " + tokenString + "\" ...")
}

func makeAuthenticatedRequest(method, url string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	// Generate token for this request
	signingKey := "K0ufhnJcbyCrNqlWfZifbrWzoLDzbcVv5sn1uoRjkc0="
	key, err := base64.StdEncoding.DecodeString(signingKey)
	if err != nil {
		return nil, err
	}
	
	claims := TestClaims{
		UserID:   "test-user-123",
		GuildID:  "221305060884348930",
		Roles:    []string{"1409555023041663006"},
		Username: "TestUser",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+tokenString)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	return client.Do(req)
}

func checkExists(sha256 string) {
	url := fmt.Sprintf("http://localhost:8080/v1/objects/exists/%s", sha256)
	resp, err := makeAuthenticatedRequest("GET", url, nil)
	if err != nil {
		log.Fatal("Request failed:", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response:", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", string(body))
}

func presignPut(sha256, sizeStr string) {
	var size int64
	fmt.Sscanf(sizeStr, "%d", &size)

	reqBody := map[string]interface{}{
		"sha256": sha256,
		"size":   size,
	}

	resp, err := makeAuthenticatedRequest("POST", "http://localhost:8080/v1/objects/presign-put", reqBody)
	if err != nil {
		log.Fatal("Request failed:", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response:", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", string(body))
}

func presignGet(sha256 string) {
	reqBody := map[string]interface{}{
		"sha256": sha256,
	}

	resp, err := makeAuthenticatedRequest("POST", "http://localhost:8080/v1/objects/presign-get", reqBody)
	if err != nil {
		log.Fatal("Request failed:", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response:", err)
	}

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Response: %s\n", string(body))
}
