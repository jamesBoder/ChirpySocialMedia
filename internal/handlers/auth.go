package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/jamesboder/ChirpySocialMedia/internal/auth"
	"github.com/jamesboder/ChirpySocialMedia/internal/respond"
)

// Refresh handles POST /api/refresh — issues a new access token from a valid refresh token.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	dbToken, err := h.DB.GetRefreshToken(r.Context(), token)
	if err != nil {
		if err == sql.ErrNoRows {
			respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		log.Printf("refresh: GetRefreshToken: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if dbToken.ExpiresAt.Before(time.Now().UTC()) || dbToken.RevokedAt.Valid {
		respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	tok, err := auth.MakeJWT(dbToken.UserID, h.JWTSecret, time.Hour)
	if err != nil {
		log.Printf("refresh: MakeJWT: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respond.WithJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// Revoke handles POST /api/revoke — invalidates a refresh token (logout).
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	_, err = h.DB.GetRefreshToken(r.Context(), token)
	if err != nil {
		if err == sql.ErrNoRows {
			respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		log.Printf("revoke: GetRefreshToken: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if err = h.DB.RevokeRefreshToken(r.Context(), token); err != nil {
		log.Printf("revoke: RevokeRefreshToken: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
