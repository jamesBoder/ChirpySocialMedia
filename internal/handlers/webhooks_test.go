package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
)

func TestPolkaWebhook_WrongAPIKey(t *testing.T) {
	h := newTestHandler(&mockStore{})

	body := `{"event":"user.upgraded","data":{"user_id":"` + uuid.New().String() + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/polka/webhooks", strings.NewReader(body))
	req.Header.Set("Authorization", "ApiKey wrong-key")
	w := httptest.NewRecorder()

	h.PolkaWebhook(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("PolkaWebhook() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestPolkaWebhook_NoAPIKey(t *testing.T) {
	h := newTestHandler(&mockStore{})

	body := `{"event":"user.upgraded","data":{"user_id":"` + uuid.New().String() + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/polka/webhooks", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.PolkaWebhook(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("PolkaWebhook() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestPolkaWebhook_NonUpgradeEvent(t *testing.T) {
	h := newTestHandler(&mockStore{})

	body := `{"event":"user.created","data":{"user_id":"` + uuid.New().String() + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/polka/webhooks", strings.NewReader(body))
	req.Header.Set("Authorization", "ApiKey "+testPolkaKey)
	w := httptest.NewRecorder()

	h.PolkaWebhook(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("PolkaWebhook() status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestPolkaWebhook_UserUpgraded(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		upgradeUserToChirpyRed: func(_ context.Context, id uuid.UUID) (database.UpgradeUserToChirpyRedRow, error) {
			return database.UpgradeUserToChirpyRedRow{
				ID:          id,
				Email:       "user@example.com",
				IsChirpyRed: true,
				CreatedAt:   now,
				UpdatedAt:   now,
			}, nil
		},
	})

	payload, _ := json.Marshal(map[string]interface{}{
		"event": "user.upgraded",
		"data":  map[string]string{"user_id": userID.String()},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/polka/webhooks", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "ApiKey "+testPolkaKey)
	w := httptest.NewRecorder()

	h.PolkaWebhook(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("PolkaWebhook() status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestPolkaWebhook_UserNotFound(t *testing.T) {
	userID := uuid.New()

	h := newTestHandler(&mockStore{
		upgradeUserToChirpyRed: func(_ context.Context, _ uuid.UUID) (database.UpgradeUserToChirpyRedRow, error) {
			return database.UpgradeUserToChirpyRedRow{}, sql.ErrNoRows
		},
	})

	payload, _ := json.Marshal(map[string]interface{}{
		"event": "user.upgraded",
		"data":  map[string]string{"user_id": userID.String()},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/polka/webhooks", strings.NewReader(string(payload)))
	req.Header.Set("Authorization", "ApiKey "+testPolkaKey)
	w := httptest.NewRecorder()

	h.PolkaWebhook(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("PolkaWebhook() status = %d, want %d", w.Code, http.StatusNotFound)
	}
}
