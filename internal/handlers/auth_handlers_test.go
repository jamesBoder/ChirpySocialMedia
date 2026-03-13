package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
)

func TestRefresh_Valid(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		getRefreshToken: func(_ context.Context, token string) (database.RefreshToken, error) {
			return database.RefreshToken{
				Token:     token,
				UserID:    userID,
				CreatedAt: now,
				UpdatedAt: now,
				ExpiresAt: now.Add(24 * time.Hour),
				RevokedAt: sql.NullTime{Valid: false},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.Header.Set("Authorization", "Bearer valid-refresh-token")
	w := httptest.NewRecorder()

	h.Refresh(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Refresh() status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Refresh() failed to decode response: %v", err)
	}
	if resp["token"] == "" {
		t.Errorf("Refresh() response missing token")
	}
}

func TestRefresh_Revoked(t *testing.T) {
	now := time.Now().UTC()
	revokedAt := now.Add(-time.Hour)

	h := newTestHandler(&mockStore{
		getRefreshToken: func(_ context.Context, token string) (database.RefreshToken, error) {
			return database.RefreshToken{
				Token:     token,
				UserID:    uuid.New(),
				CreatedAt: now,
				UpdatedAt: now,
				ExpiresAt: now.Add(24 * time.Hour),
				RevokedAt: sql.NullTime{Time: revokedAt, Valid: true},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.Header.Set("Authorization", "Bearer revoked-token")
	w := httptest.NewRecorder()

	h.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Refresh() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRefresh_Expired(t *testing.T) {
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		getRefreshToken: func(_ context.Context, token string) (database.RefreshToken, error) {
			return database.RefreshToken{
				Token:     token,
				UserID:    uuid.New(),
				CreatedAt: now,
				UpdatedAt: now,
				ExpiresAt: now.Add(-time.Hour), // already expired
				RevokedAt: sql.NullTime{Valid: false},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()

	h.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Refresh() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRefresh_TokenNotFound(t *testing.T) {
	h := newTestHandler(&mockStore{
		getRefreshToken: func(_ context.Context, _ string) (database.RefreshToken, error) {
			return database.RefreshToken{}, sql.ErrNoRows
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	req.Header.Set("Authorization", "Bearer unknown-token")
	w := httptest.NewRecorder()

	h.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Refresh() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRefresh_NoAuthHeader(t *testing.T) {
	h := newTestHandler(&mockStore{})

	req := httptest.NewRequest(http.MethodPost, "/api/refresh", nil)
	w := httptest.NewRecorder()

	h.Refresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Refresh() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRevoke_Success(t *testing.T) {
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		getRefreshToken: func(_ context.Context, token string) (database.RefreshToken, error) {
			return database.RefreshToken{
				Token:     token,
				UserID:    uuid.New(),
				CreatedAt: now,
				UpdatedAt: now,
				ExpiresAt: now.Add(24 * time.Hour),
			}, nil
		},
		revokeRefreshToken: func(_ context.Context, _ string) error { return nil },
	})

	req := httptest.NewRequest(http.MethodPost, "/api/revoke", nil)
	req.Header.Set("Authorization", "Bearer valid-refresh-token")
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Revoke() status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestRevoke_TokenNotFound(t *testing.T) {
	h := newTestHandler(&mockStore{
		getRefreshToken: func(_ context.Context, _ string) (database.RefreshToken, error) {
			return database.RefreshToken{}, sql.ErrNoRows
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/revoke", nil)
	req.Header.Set("Authorization", "Bearer unknown-token")
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Revoke() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
