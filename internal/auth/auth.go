package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {
	// Hash password using argon2id.CreateHash
	params := argon2id.DefaultParams
	hash, err := argon2id.CreateHash(password, params)
	if err != nil {
		return "", err
	}
	return hash, nil

}

func ComparePasswordHash(password, hash string) (bool, error) {
	// Compare password and hash using argon2id.ComparePasswordAndHash
	return argon2id.ComparePasswordAndHash(password, hash)
}

// Make JWT function
func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	// go
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	})
	// sign token with token secret
	return token.SignedString([]byte(tokenSecret))
}

// Add a validaate JWT function
func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// parse token with jwt.ParseWithClaims
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	// check if token is valid
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		// parse user ID from subject
		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			return uuid.Nil, err
		}
		return userID, nil
	} else {
		return uuid.Nil, err
	}
}

// go
func GetBearerToken(h http.Header) (string, error) {
	auth := h.Get("Authorization")
	if auth == "" {
		return "", fmt.Errorf("no auth header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return "", fmt.Errorf("malformed authorization header")
	}
	return parts[1], nil
}

// Add MakeRefreshToken function
func MakeRefreshToken() (string, error) {
	// generate a random 256-bit (32-byte) hex-encoded string. use rand.Read and hex.EncodeToString
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	hexStr := hex.EncodeToString(key)
	return hexStr, nil

}
