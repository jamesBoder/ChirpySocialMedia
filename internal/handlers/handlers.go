package handlers

import (
	"net/http"
	"regexp"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jamesboder/ChirpySocialMedia/internal/auth"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
	"github.com/jamesboder/ChirpySocialMedia/internal/respond"
)

// jwtPattern matches the three-part header.payload.signature format.
var jwtPattern = regexp.MustCompile(`^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$`)

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	DB          *database.Queries
	JWTSecret   string
	PolkaKey    string
	Platform    string
	FileHits    atomic.Int32
}

// requireAuth extracts and validates the JWT from the Authorization header.
// Returns the authenticated user's UUID, or writes a 401 and returns an error.
func (h *Handler) requireAuth(w http.ResponseWriter, r *http.Request) (uuid.UUID, error) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
		return uuid.Nil, err
	}

	if !jwtPattern.MatchString(token) {
		respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
		return uuid.Nil, auth.ErrInvalidToken
	}

	userID, err := auth.ValidateJWT(token, h.JWTSecret)
	if err != nil {
		respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
		return uuid.Nil, err
	}

	return userID, nil
}
