package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Create test validate JWT function
func TestValidateJWT(t *testing.T) {
	// create a new user ID
	userID := uuid.New()
	// create a token secret
	tokenSecret := "mysecret"

	// create a token that expires in 1 hour
	tokenString, err := MakeJWT(userID, tokenSecret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}

	// validate the token
	returnedUserID, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil {
		t.Fatalf("ValidateJWT() error = %v", err)
	}
	if returnedUserID != userID {
		t.Errorf("ValidateJWT() = %v, want %v", returnedUserID, userID)
	}

	// test with an invalid token
	_, err = ValidateJWT(tokenString+"invalid", tokenSecret)
	if err == nil {
		t.Errorf("ValidateJWT() expected error for invalid token, got nil")
	}

	// test with an expired token
	expiredTokenString, err := MakeJWT(userID, tokenSecret, -time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}
	_, err = ValidateJWT(expiredTokenString, tokenSecret)
	if err == nil {
		t.Errorf("ValidateJWT() expected error for expired token, got nil")
	}
}

// Add a test for make JWT function
func TestMakeJWT(t *testing.T) {
	// create a new user ID
	userID := uuid.New()
	// create a token secret
	tokenSecret := "mysecret"
	// create a token that expires in 1 hour
	tokenString, err := MakeJWT(userID, tokenSecret, time.Hour)
	if err != nil {
		t.Fatalf("MakeJWT() error = %v", err)
	}
	if tokenString == "" {
		t.Errorf("MakeJWT() = empty token string")
	}
}

// Add a test for GetBearerToken function
func TestGetBearerToken(t *testing.T) {
	// create a header with a bearer token
	headers := http.Header{}
	headers.Set("Authorization", "Bearer mytoken")
	// get the bearer token
	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("GetBearerToken() error = %v", err)
	}
	if token != "mytoken" {
		t.Errorf("GetBearerToken() = %v, want %v", token, "mytoken")
	}

	// test with no authorization header
	headers = http.Header{}
	_, err = GetBearerToken(headers)
	if err == nil {
		t.Errorf("GetBearerToken() expected error for missing header, got nil")
	}
	// test with invalid authorization header
	headers = http.Header{}
	headers.Set("Authorization", "InvalidHeader")
	_, err = GetBearerToken(headers)
	if err == nil {
		t.Errorf("GetBearerToken() expected error for invalid header, got nil")
	}

}
