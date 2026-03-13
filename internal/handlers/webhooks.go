package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/jamesboder/ChirpySocialMedia/internal/auth"
	"github.com/jamesboder/ChirpySocialMedia/internal/respond"
)

// PolkaWebhook handles POST /api/polka/webhooks.
// Upgrades a user to Chirpy Red when event is "user.upgraded".
func (h *Handler) PolkaWebhook(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != h.PolkaKey {
		respond.WithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		Event string          `json:"event"`
		Data  json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.WithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}

	if req.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var data struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(req.Data, &data); err != nil {
		respond.WithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}

	uid, err := uuid.Parse(data.UserID)
	if err != nil {
		respond.WithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	_, err = h.DB.UpgradeUserToChirpyRed(r.Context(), uid)
	if err != nil {
		if err == sql.ErrNoRows {
			respond.WithError(w, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("polkaWebhook: UpgradeUserToChirpyRed: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
