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

func TestFilterProfanity(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hello world", "Hello world"},
		{"What a kerfuffle!", "What a ****!"},
		{"You sharbert!", "You ****!"},
		{"Look at fornax", "Look at ****"},
		{"KERFUFFLE is loud", "**** is loud"},
		{"kerfuffle sharbert fornax", "**** **** ****"},
	}

	for _, tc := range tests {
		got := filterProfanity(tc.input)
		if got != tc.want {
			t.Errorf("filterProfanity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestCreateChirp_Success(t *testing.T) {
	userID := uuid.New()
	chirpID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		createChirp: func(_ context.Context, arg database.CreateChirpParams) (database.CreateChirpRow, error) {
			return database.CreateChirpRow{
				ID:        chirpID,
				Body:      arg.Body,
				UserID:    arg.UserID,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	})

	body := `{"body":"Hello, Chirpy!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(body))
	req.Header.Set("Authorization", makeAuthHeader(userID))
	w := httptest.NewRecorder()

	h.CreateChirp(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("CreateChirp() status = %d, want %d", w.Code, http.StatusCreated)
	}
	var resp chirpResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("CreateChirp() failed to decode response: %v", err)
	}
	if resp.Body != "Hello, Chirpy!" {
		t.Errorf("CreateChirp() body = %q, want %q", resp.Body, "Hello, Chirpy!")
	}
}

func TestCreateChirp_Unauthenticated(t *testing.T) {
	h := newTestHandler(&mockStore{})

	body := `{"body":"Hello!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.CreateChirp(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("CreateChirp() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestCreateChirp_TooLong(t *testing.T) {
	userID := uuid.New()
	h := newTestHandler(&mockStore{})

	longBody := strings.Repeat("x", maxChirpLength+1)
	body := `{"body":"` + longBody + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(body))
	req.Header.Set("Authorization", makeAuthHeader(userID))
	w := httptest.NewRecorder()

	h.CreateChirp(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("CreateChirp() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateChirp_FiltersProfanity(t *testing.T) {
	userID := uuid.New()
	chirpID := uuid.New()
	now := time.Now().UTC()

	var savedBody string
	h := newTestHandler(&mockStore{
		createChirp: func(_ context.Context, arg database.CreateChirpParams) (database.CreateChirpRow, error) {
			savedBody = arg.Body
			return database.CreateChirpRow{
				ID:        chirpID,
				Body:      arg.Body,
				UserID:    arg.UserID,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	})

	body := `{"body":"What a kerfuffle!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(body))
	req.Header.Set("Authorization", makeAuthHeader(userID))
	w := httptest.NewRecorder()

	h.CreateChirp(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("CreateChirp() status = %d, want %d", w.Code, http.StatusCreated)
	}
	if savedBody != "What a ****!" {
		t.Errorf("CreateChirp() stored body = %q, want profanity filtered", savedBody)
	}
}

func TestListChirps_Empty(t *testing.T) {
	h := newTestHandler(&mockStore{
		getAllChirps: func(_ context.Context) ([]database.GetAllChirpsRow, error) {
			return nil, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/chirps", nil)
	w := httptest.NewRecorder()

	h.ListChirps(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ListChirps() status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp []chirpResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("ListChirps() failed to decode response: %v", err)
	}
	if len(resp) != 0 {
		t.Errorf("ListChirps() returned %d chirps, want 0", len(resp))
	}
}

func TestListChirps_WithData(t *testing.T) {
	now := time.Now().UTC()
	chirpID := uuid.New()
	userID := uuid.New()

	h := newTestHandler(&mockStore{
		getAllChirps: func(_ context.Context) ([]database.GetAllChirpsRow, error) {
			return []database.GetAllChirpsRow{
				{ID: chirpID, Body: "Test chirp", UserID: userID, CreatedAt: now, UpdatedAt: now},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/chirps", nil)
	w := httptest.NewRecorder()

	h.ListChirps(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ListChirps() status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp []chirpResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("ListChirps() failed to decode response: %v", err)
	}
	if len(resp) != 1 {
		t.Fatalf("ListChirps() returned %d chirps, want 1", len(resp))
	}
	if resp[0].Body != "Test chirp" {
		t.Errorf("ListChirps() chirp body = %q, want %q", resp[0].Body, "Test chirp")
	}
}

func TestListChirps_InvalidSortParam(t *testing.T) {
	h := newTestHandler(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/chirps?sort=invalid", nil)
	w := httptest.NewRecorder()

	h.ListChirps(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("ListChirps() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestGetChirp_Found(t *testing.T) {
	chirpID := uuid.New()
	userID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		getChirp: func(_ context.Context, id uuid.UUID) (database.GetChirpRow, error) {
			return database.GetChirpRow{
				ID:        id,
				Body:      "Hello",
				UserID:    userID,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/chirps/"+chirpID.String(), nil)
	req.SetPathValue("chirpID", chirpID.String())
	w := httptest.NewRecorder()

	h.GetChirp(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetChirp() status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestGetChirp_NotFound(t *testing.T) {
	chirpID := uuid.New()

	h := newTestHandler(&mockStore{
		getChirp: func(_ context.Context, _ uuid.UUID) (database.GetChirpRow, error) {
			return database.GetChirpRow{}, sql.ErrNoRows
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/chirps/"+chirpID.String(), nil)
	req.SetPathValue("chirpID", chirpID.String())
	w := httptest.NewRecorder()

	h.GetChirp(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("GetChirp() status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestGetChirp_InvalidID(t *testing.T) {
	h := newTestHandler(&mockStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/chirps/not-a-uuid", nil)
	req.SetPathValue("chirpID", "not-a-uuid")
	w := httptest.NewRecorder()

	h.GetChirp(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("GetChirp() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestDeleteChirp_Success(t *testing.T) {
	userID := uuid.New()
	chirpID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		getChirp: func(_ context.Context, id uuid.UUID) (database.GetChirpRow, error) {
			return database.GetChirpRow{
				ID:        id,
				Body:      "chirp",
				UserID:    userID,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
		deleteChirp: func(_ context.Context, _ uuid.UUID) error { return nil },
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.Header.Set("Authorization", makeAuthHeader(userID))
	req.SetPathValue("chirpID", chirpID.String())
	w := httptest.NewRecorder()

	h.DeleteChirp(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("DeleteChirp() status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestDeleteChirp_Forbidden(t *testing.T) {
	authorID := uuid.New()
	otherUserID := uuid.New()
	chirpID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		getChirp: func(_ context.Context, id uuid.UUID) (database.GetChirpRow, error) {
			return database.GetChirpRow{
				ID:        id,
				Body:      "chirp",
				UserID:    authorID, // owned by authorID
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.Header.Set("Authorization", makeAuthHeader(otherUserID)) // different user
	req.SetPathValue("chirpID", chirpID.String())
	w := httptest.NewRecorder()

	h.DeleteChirp(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("DeleteChirp() status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestDeleteChirp_Unauthenticated(t *testing.T) {
	h := newTestHandler(&mockStore{})

	chirpID := uuid.New()
	req := httptest.NewRequest(http.MethodDelete, "/api/chirps/"+chirpID.String(), nil)
	req.SetPathValue("chirpID", chirpID.String())
	w := httptest.NewRecorder()

	h.DeleteChirp(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("DeleteChirp() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
