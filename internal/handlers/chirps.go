package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
	"github.com/jamesboder/ChirpySocialMedia/internal/respond"
)

const maxChirpLength = 140

var profaneWords = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bkerfuffle\b`),
	regexp.MustCompile(`(?i)\bsharbert\b`),
	regexp.MustCompile(`(?i)\bfornax\b`),
}

type chirpResponse struct {
	ID        string `json:"id"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func filterProfanity(s string) string {
	for _, re := range profaneWords {
		s = re.ReplaceAllString(s, "****")
	}
	return s
}

func chirpRow(id uuid.UUID, body string, userID uuid.UUID, createdAt, updatedAt time.Time) chirpResponse {
	return chirpResponse{
		ID:        id.String(),
		Body:      body,
		UserID:    userID.String(),
		CreatedAt: createdAt.UTC().Format(time.RFC3339),
		UpdatedAt: updatedAt.UTC().Format(time.RFC3339),
	}
}

// CreateChirp handles POST /api/chirps.
func (h *Handler) CreateChirp(w http.ResponseWriter, r *http.Request) {
	userID, err := h.requireAuth(w, r)
	if err != nil {
		return
	}

	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respond.WithError(w, http.StatusBadRequest, "Something went wrong")
		return
	}
	if req.Body == "" {
		respond.WithError(w, http.StatusBadRequest, "Chirp body is required")
		return
	}
	if len(req.Body) > maxChirpLength {
		respond.WithError(w, http.StatusBadRequest, fmt.Sprintf("Chirp is too long (max %d characters)", maxChirpLength))
		return
	}

	cleaned := filterProfanity(req.Body)

	c, err := h.DB.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleaned,
		UserID: userID,
	})
	if err != nil {
		log.Printf("createChirp: CreateChirp: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respond.WithJSON(w, http.StatusCreated, chirpRow(c.ID, c.Body, c.UserID, c.CreatedAt, c.UpdatedAt))
}

// ListChirps handles GET /api/chirps.
// Supports ?author_id=<uuid> and ?sort=asc|desc query parameters.
func (h *Handler) ListChirps(w http.ResponseWriter, r *http.Request) {
	sortOrder := r.URL.Query().Get("sort")
	if sortOrder != "" && sortOrder != "asc" && sortOrder != "desc" {
		respond.WithError(w, http.StatusBadRequest, "Invalid sort parameter")
		return
	}

	authorIDStr := r.URL.Query().Get("author_id")

	var chirps []chirpResponse

	if authorIDStr != "" {
		aid, err := uuid.Parse(authorIDStr)
		if err != nil {
			respond.WithError(w, http.StatusBadRequest, "Invalid author ID")
			return
		}
		rows, err := h.DB.GetChirpsByAuthor(r.Context(), aid)
		if err != nil {
			log.Printf("listChirps: GetChirpsByAuthor: %v", err)
			respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		for _, c := range rows {
			chirps = append(chirps, chirpRow(c.ID, c.Body, c.UserID, c.CreatedAt, c.UpdatedAt))
		}
		if sortOrder == "desc" {
			sort.Slice(chirps, func(i, j int) bool {
				return chirps[i].CreatedAt > chirps[j].CreatedAt
			})
		}
	} else if sortOrder == "desc" {
		rows, err := h.DB.GetAllChirpsDesc(r.Context())
		if err != nil {
			log.Printf("listChirps: GetAllChirpsDesc: %v", err)
			respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		for _, c := range rows {
			chirps = append(chirps, chirpRow(c.ID, c.Body, c.UserID, c.CreatedAt, c.UpdatedAt))
		}
	} else {
		rows, err := h.DB.GetAllChirps(r.Context())
		if err != nil {
			log.Printf("listChirps: GetAllChirps: %v", err)
			respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
			return
		}
		for _, c := range rows {
			chirps = append(chirps, chirpRow(c.ID, c.Body, c.UserID, c.CreatedAt, c.UpdatedAt))
		}
	}

	if chirps == nil {
		chirps = []chirpResponse{}
	}
	respond.WithJSON(w, http.StatusOK, chirps)
}

// GetChirp handles GET /api/chirps/{chirpID}.
func (h *Handler) GetChirp(w http.ResponseWriter, r *http.Request) {
	cid, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respond.WithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	c, err := h.DB.GetChirp(r.Context(), cid)
	if err != nil {
		if err == sql.ErrNoRows {
			respond.WithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		log.Printf("getChirp: GetChirp: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	respond.WithJSON(w, http.StatusOK, chirpRow(c.ID, c.Body, c.UserID, c.CreatedAt, c.UpdatedAt))
}

// DeleteChirp handles DELETE /api/chirps/{chirpID}.
// Only the author of the chirp may delete it.
func (h *Handler) DeleteChirp(w http.ResponseWriter, r *http.Request) {
	userID, err := h.requireAuth(w, r)
	if err != nil {
		return
	}

	cid, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respond.WithError(w, http.StatusBadRequest, "Invalid chirp ID")
		return
	}

	c, err := h.DB.GetChirp(r.Context(), cid)
	if err != nil {
		if err == sql.ErrNoRows {
			respond.WithError(w, http.StatusNotFound, "Chirp not found")
			return
		}
		log.Printf("deleteChirp: GetChirp: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if c.UserID != userID {
		respond.WithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	if err = h.DB.DeleteChirp(r.Context(), cid); err != nil {
		log.Printf("deleteChirp: DeleteChirp: %v", err)
		respond.WithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
