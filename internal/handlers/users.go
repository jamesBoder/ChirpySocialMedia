package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/jamesboder/ChirpySocialMedia/internal/auth"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
	"github.com/jamesboder/ChirpySocialMedia/internal/respond"
)

type userResponse struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

func userToResponse(u database.User) userResponse {
	return userResponse{
		ID:          u.ID.String(),
		Email:       u.Email,
		CreatedAt:   u.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   u.UpdatedAt.UTC().Format(time.RFC3339),
		IsChirpyRed: u.IsChirpyRed,
	}
}

func updateUserRowToResponse(u database.UpdateUserRow) userResponse {
	return userResponse{
		ID:          u.ID.String(),
		Email:       u.Email,
		CreatedAt:   u.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:   u.UpdatedAt.UTC().Format(time.RFC3339),
		IsChirpyRed: u.IsChirpyRed,
	}
}

// Register handles POST /api/users — creates a new user account.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.WithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	if req.Email == "" {
		respond.WithError(w, http.StatusBadRequest, "Email is required")
		return
	}
	if req.Password == "" {
		respond.WithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	hashed, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("register: hash password: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := h.DB.CreateUser(r.Context(), database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		log.Printf("register: CreateUser: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respond.WithJSON(w, http.StatusCreated, userToResponse(user))
}

// Login handles POST /api/login — authenticates a user and returns JWT + refresh token.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.WithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	if req.Email == "" {
		respond.WithError(w, http.StatusBadRequest, "Email is required")
		return
	}
	if req.Password == "" {
		respond.WithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	user, err := h.DB.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			respond.WithError(w, http.StatusUnauthorized, "Incorrect email or password")
			return
		}
		log.Printf("login: GetUserByEmail: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	match, err := auth.ComparePasswordHash(req.Password, user.HashedPassword)
	if err != nil || !match {
		respond.WithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	tok, err := auth.MakeJWT(user.ID, h.JWTSecret, time.Hour)
	if err != nil {
		log.Printf("login: MakeJWT: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	refreshTok, err := auth.MakeRefreshToken()
	if err != nil {
		log.Printf("login: MakeRefreshToken: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if err = h.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshTok,
		UserID:    user.ID,
		ExpiresAt: time.Now().UTC().Add(60 * 24 * time.Hour),
	}); err != nil {
		log.Printf("login: CreateRefreshToken: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	type loginResponse struct {
		userResponse
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	respond.WithJSON(w, http.StatusOK, loginResponse{
		userResponse: userToResponse(user),
		Token:        tok,
		RefreshToken: refreshTok,
	})
}

// UpdateUser handles PUT /api/users — updates the authenticated user's email and password.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := h.requireAuth(w, r)
	if err != nil {
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.WithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	if req.Email == "" {
		respond.WithError(w, http.StatusBadRequest, "Email is required")
		return
	}
	if req.Password == "" {
		respond.WithError(w, http.StatusBadRequest, "Password is required")
		return
	}

	hashed, err := auth.HashPassword(req.Password)
	if err != nil {
		log.Printf("updateUser: hash password: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := h.DB.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userID,
		Email:          req.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		log.Printf("updateUser: UpdateUser: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respond.WithJSON(w, http.StatusOK, updateUserRowToResponse(user))
}
