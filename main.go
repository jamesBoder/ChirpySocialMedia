package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/jamesboder/ChirpySocialMedia/internal/config"
	"github.com/jamesboder/ChirpySocialMedia/internal/database"
	"github.com/jamesboder/ChirpySocialMedia/internal/handlers"
	"github.com/jamesboder/ChirpySocialMedia/internal/middleware"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, reading from environment")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	db, err := sql.Open("postgres", cfg.DBURL)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	h := &handlers.Handler{
		DB:        database.New(db),
		JWTSecret: cfg.JWTSecret,
		PolkaKey:  cfg.PolkaKey,
		Platform:  cfg.Platform,
	}

	mux := http.NewServeMux()
	registerRoutes(mux, h)

	logger := log.New(os.Stdout, "", log.LstdFlags)
	corsOrigin := os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		corsOrigin = "*"
	}

	handler := middleware.Chain(mux,
		middleware.Recover(logger),
		middleware.Logger(logger),
		middleware.CORS(corsOrigin),
	)

	log.Printf("Starting server on %s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, handler); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func registerRoutes(mux *http.ServeMux, h *handlers.Handler) {
	// File server at /app/
	fsHandler := h.MetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	mux.Handle("GET /app", http.RedirectHandler("/app/", http.StatusMovedPermanently))
	mux.Handle("/app/", fsHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
			return
		}
		http.NotFound(w, r)
	})

	// Health
	mux.HandleFunc("GET /api/healthz", h.Healthz)
	mux.HandleFunc("/api/healthz", methodNotAllowed)

	// Admin
	mux.HandleFunc("GET /admin/metrics", h.Metrics)
	mux.HandleFunc("/admin/metrics", methodNotAllowed)
	mux.HandleFunc("POST /admin/reset", h.Reset)
	mux.HandleFunc("/admin/reset", methodNotAllowed)

	// Users
	mux.HandleFunc("POST /api/users", h.Register)
	mux.HandleFunc("PUT /api/users", h.UpdateUser)
	mux.HandleFunc("/api/users", methodNotAllowed)

	// Auth
	mux.HandleFunc("POST /api/login", h.Login)
	mux.HandleFunc("POST /api/refresh", h.Refresh)
	mux.HandleFunc("POST /api/revoke", h.Revoke)

	// Chirps
	mux.HandleFunc("POST /api/chirps", h.CreateChirp)
	mux.HandleFunc("GET /api/chirps", h.ListChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", h.GetChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", h.DeleteChirp)

	// Webhooks
	mux.HandleFunc("POST /api/polka/webhooks", h.PolkaWebhook)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
