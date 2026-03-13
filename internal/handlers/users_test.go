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
	"github.com/jamesboder/ChirpySocialMedia/internal/auth"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
)

// mustHashPassword is a test helper that panics on error.
func mustHashPassword(pw string) string {
	h, err := auth.HashPassword(pw)
	if err != nil {
		panic("mustHashPassword: " + err.Error())
	}
	return h
}

func TestRegister_Success(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		createUser: func(_ context.Context, arg database.CreateUserParams) (database.User, error) {
			return database.User{
				ID:        userID,
				Email:     arg.Email,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	})

	body := `{"email":"test@example.com","password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Register(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Register() status = %d, want %d", w.Code, http.StatusCreated)
	}
	var resp userResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Register() failed to decode response: %v", err)
	}
	if resp.Email != "test@example.com" {
		t.Errorf("Register() email = %q, want %q", resp.Email, "test@example.com")
	}
	if resp.ID != userID.String() {
		t.Errorf("Register() id = %q, want %q", resp.ID, userID.String())
	}
}

func TestRegister_MissingEmail(t *testing.T) {
	h := newTestHandler(&mockStore{})

	body := `{"password":"secret123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Register() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegister_MissingPassword(t *testing.T) {
	h := newTestHandler(&mockStore{})

	body := `{"email":"test@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Register(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Register() status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestLogin_Success(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()
	hashedPW := mustHashPassword("correct-password")

	h := newTestHandler(&mockStore{
		getUserByEmail: func(_ context.Context, _ string) (database.User, error) {
			return database.User{
				ID:             userID,
				Email:          "user@example.com",
				HashedPassword: hashedPW,
				CreatedAt:      now,
				UpdatedAt:      now,
			}, nil
		},
		createRefreshToken: func(_ context.Context, _ database.CreateRefreshTokenParams) error {
			return nil
		},
	})

	body := `{"email":"user@example.com","password":"correct-password"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Login(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Login() status = %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Login() failed to decode response: %v", err)
	}
	if resp["token"] == nil || resp["token"] == "" {
		t.Errorf("Login() response missing token")
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Errorf("Login() response missing refresh_token")
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	h := newTestHandler(&mockStore{
		getUserByEmail: func(_ context.Context, _ string) (database.User, error) {
			return database.User{}, sql.ErrNoRows
		},
	})

	body := `{"email":"nobody@example.com","password":"password"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Login() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()
	hashedPW := mustHashPassword("correct-password")

	h := newTestHandler(&mockStore{
		getUserByEmail: func(_ context.Context, _ string) (database.User, error) {
			return database.User{
				ID:             userID,
				Email:          "user@example.com",
				HashedPassword: hashedPW,
				CreatedAt:      now,
				UpdatedAt:      now,
			}, nil
		},
	})

	body := `{"email":"user@example.com","password":"wrong-password"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.Login(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Login() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestUpdateUser_Success(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()

	h := newTestHandler(&mockStore{
		updateUser: func(_ context.Context, arg database.UpdateUserParams) (database.UpdateUserRow, error) {
			return database.UpdateUserRow{
				ID:        arg.ID,
				Email:     arg.Email,
				CreatedAt: now,
				UpdatedAt: now,
			}, nil
		},
	})

	body := `{"email":"new@example.com","password":"newpassword"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users", strings.NewReader(body))
	req.Header.Set("Authorization", makeAuthHeader(userID))
	w := httptest.NewRecorder()

	h.UpdateUser(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("UpdateUser() status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestUpdateUser_Unauthenticated(t *testing.T) {
	h := newTestHandler(&mockStore{})

	body := `{"email":"new@example.com","password":"newpassword"}`
	req := httptest.NewRequest(http.MethodPut, "/api/users", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.UpdateUser(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("UpdateUser() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
