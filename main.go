package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/jamesboder/ChirpySocialMedia/internal/auth"

	"github.com/google/uuid"

	"github.com/jamesboder/ChirpySocialMedia/internal/database"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

func main() {

	// call godotenv
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Debug log the environment variables ****
	log.Printf("DB_URL=%q", os.Getenv("DB_URL"))
	log.Printf("PLATFORM=%q", os.Getenv("PLATFORM"))

	// Connect to the database
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL environment variable not set")
	}

	// Open a connection to the database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	defer db.Close()

	// Read PLATFORM environment variable
	platform := os.Getenv("PLATFORM")
	if platform == "" {
		log.Println("PLATFORM environment variable not set, defaulting to dev")
		platform = "dev"
	}

	// Create a new http.ServeMux
	mux := http.NewServeMux()

	// Create a new http.Server struct
	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Create an instance of the apiConfig struct
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		dbQueries:      database.New(db),
		platform:       platform,
	}

	// use NewServeMux .Handle() to add a handler for the root path "/". Use .FileServer as the handler
	handler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))

	//mux.Handle("/app", handler)  // serves index.html on /app
	// redirect /app to /app/
	mux.Handle("GET /app", http.RedirectHandler("/app/", http.StatusMovedPermanently))

	mux.Handle("/app/", handler) // serves other assets under /app/

	// catch-all 404 so unmatched methods don’t hit the file server
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	// Add a /healthz endpoint to the main function. update to only respond to GET requests. Other methods should return a 405 status code.
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/api/healthz", methodNotAllowed)

	// Add the /metrics endpoint to the main function that responds to GET requests only. returns HTML to be rendered in the browser

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("/admin/metrics", methodNotAllowed)

	//log.Println("Registered /metrics handler") // Add this line for debugging

	// Add the /reset endpoint to the main function
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("/admin/reset", methodNotAllowed)

	// Add POST /api/chirps handler that accepts JSON body with "body" field, if chirp is valid save to database with id, created_at, updated_at, body, user_id (use any valid user_id from users table). Return 201 with JSON response containing chirp data. If invalid return 400 with JSON error message.
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {

		// init struct to hold incoming JSON data
		type chirp struct {
			Body   string `json:"body"`
			UserID string `json:"user_id"`
		}

		// init struct to hold outgoing JSON data
		type chirpResponse struct {
			ID        string `json:"id"`
			Body      string `json:"body"`
			UserID    string `json:"user_id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}

		// decode the JSON body and user_id into the chirp struct
		decoder := json.NewDecoder(r.Body)
		var c chirp
		err := decoder.Decode(&c)
		if err != nil {
			log.Printf("error decoding JSON: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Validate c.Body == "". if invalid respond with 400 status code
		if c.Body == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Chirp body is required"})
			w.Write(dat)
			return
		}

		// if user_id is empty respond with 400 status code
		if c.UserID == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "User ID is required"})
			w.Write(dat)
			return
		}

		// Validate the chirp body length
		if len(c.Body) > 140 {
			// If the chirp body is too long, respond with a 400 status code and a JSON response indicating the error
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			resp := map[string]string{"error": "Chirp is too long"}
			jsonResp, _ := json.Marshal(resp)
			w.Write(jsonResp)
			return
		}

		// IF lenght validation passed replace profane words with 4 asterisks. the words are "kerfuffle", "sharbert", and "fornax". Match upper and lower case versions but not punctuation-attached versions. Return the cleaned chirp in the JSON response
		// Example: {"valid": true, "cleaned_chirp": "This is a **** example"}
		profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
		cleanedChirp := c.Body
		for _, word := range profaneWords {
			//replacer := fmt.Sprintf("(?i)%s", word) // case-insensitive regex
			// Build cleanedChirp using case-insensitive, whole-word regex for each profane word using (?i)\b<word>\b
			re := regexp.MustCompile(fmt.Sprintf(`(?i)\b%s\b`, word))
			cleanedChirp = re.ReplaceAllString(cleanedChirp, "****")

		}

		uid, err := uuid.Parse(c.UserID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
			return
		}

		// Insert the chirp into the database
		newChirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   cleanedChirp,
			UserID: uid,
		})
		if err != nil {
			log.Printf("error inserting chirp into database: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Respond with a 201 status code and a JSON response containing the chirp data
		resp := chirpResponse{
			ID:        newChirp.ID.String(),
			Body:      newChirp.Body,
			UserID:    newChirp.UserID.String(),
			CreatedAt: newChirp.CreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt: newChirp.UpdatedAt.UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)

	})

	//mux.HandleFunc("/api/chirps", methodNotAllowed) // handled in the function above

	// Add GET /api/chirps handler that returns a JSON array of all chirps in the database, ordered by created_at ascending order. Each chirp should include id, created_at, updated_at, body, user_id
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		// Define a struct to hold the chirp data
		type chirpResponse struct {
			ID        string `json:"id"`
			Body      string `json:"body"`
			UserID    string `json:"user_id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}

		// Get all chirps from the database ordered by created_at ascending
		chirps, err := apiCfg.dbQueries.GetAllChirps(r.Context())
		if err != nil {
			log.Printf("error getting chirps from database: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Create a slice to hold the chirp responses
		var resp []chirpResponse

		// Loop through the chirps and append them to the response slice
		for _, c := range chirps {
			resp = append(resp, chirpResponse{
				ID:        c.ID.String(),
				Body:      c.Body,
				UserID:    c.UserID.String(),
				CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339),
				UpdatedAt: c.UpdatedAt.UTC().Format(time.RFC3339),
			})
		}

		// Respond with a 200 status code and a JSON array of chirps
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})

	// Add a GET /api/chirps/{chirpID} endpoint that returns a single chirp by its ID. If the chirp is not found, return a 404 status code with a JSON error message.
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		// Define a struct to hold the chirp data
		type chirpResponse struct {
			ID        string `json:"id"`
			Body      string `json:"body"`
			UserID    string `json:"user_id"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}

		// Get string value of chirpID using http.Request.PathValue
		chirpID := r.PathValue("chirpID")

		// Parse chirpID
		cid, err := uuid.Parse(chirpID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Invalid chirp ID"})
			return
		}

		// Get the chirp from the database
		chirp, err := apiCfg.dbQueries.GetChirp(r.Context(), cid)
		if err != nil {
			if err == sql.ErrNoRows {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "Chirp not found"})
				return
			}
			log.Printf("error getting chirp from database: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Respond with a 200 status code and a JSON object of the chirp
		resp := chirpResponse{
			ID:        chirp.ID.String(),
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
			CreatedAt: chirp.CreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt: chirp.UpdatedAt.UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	})

	// Add a new endpoint to your server POST /api/users that accepts an email as JSON in body and returns user's ID, email and timestamps
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		log.Println("POST /api/users start")
		defer log.Println("POST /api/users end")

		// init struct to hold incoming JSON data
		type userRequest struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		// init struct to hold outgoing JSON data
		type userResponse struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}

		// decode the JSON body into the userRequest struct
		decoder := json.NewDecoder(r.Body)
		var ur userRequest

		err := decoder.Decode(&ur)
		if err != nil {
			log.Printf("error decoding JSON: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Validate ur.Password == "". if invalid respond with 400 status code
		if ur.Password == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Password is required"})
			w.Write(dat)
			return
		}

		// Validate ur.Email == "". if invalid respond with 400 status code
		if ur.Email == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Email is required"})
			w.Write(dat)
			return
		}

		// hash the password using the auth package
		hashedPassword, err := auth.HashPassword(ur.Password)
		if err != nil {
			log.Printf("error hashing password: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// set ur.Password to the hashed password
		ur.Password = hashedPassword

		// Debug log the email being created
		log.Printf("CreateUser arg email=%q", ur.Email)

		// Insert the user email and hashed password into the database
		user, err := apiCfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
			Email:          ur.Email,
			HashedPassword: ur.Password,
		})
		if err != nil {
			log.Printf("error inserting user into database: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Respond with a 201 status code and a JSON response containing the user's ID, email, and timestamps

		resp := userResponse{
			ID:        user.ID.String(),
			Email:     user.Email,
			CreatedAt: user.CreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt: user.UpdatedAt.UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)

	})

	// Handle non-POST requests to /api/users with 405
	mux.HandleFunc("/api/users", methodNotAllowed)

	// Add a POST /api/login endpoint. It should allow a user to log in with their email and password. If both are valid return a 200 ok status code with a JSON response without the password. If the email is not found or the password is incorrect return a 401 status code with a JSON error message.
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		log.Println("POST /api/login start")
		defer log.Println("POST /api/login end")

		// init struct to hold incoming JSON data
		type loginRequest struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		// init struct to hold outgoing JSON data
		type loginResponse struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			CreatedAt string `json:"created_at"`
			UpdatedAt string `json:"updated_at"`
		}

		// decode the JSON body into the loginRequest struct
		decoder := json.NewDecoder(r.Body)
		var lr loginRequest
		err := decoder.Decode(&lr)
		if err != nil {
			log.Printf("error decoding JSON: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Validate lr.Email == "". if invalid respond with 400 status code
		if lr.Email == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Email is required"})
			w.Write(dat)
			return
		}

		// Validate lr.Password == "". if invalid respond with 400 status code
		if lr.Password == "" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Password is required"})
			w.Write(dat)
			return
		}

		// Get the user from the database by email
		user, err := apiCfg.dbQueries.GetUserByEmail(r.Context(), lr.Email)
		if err != nil {
			if err == sql.ErrNoRows {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				dat, _ := json.Marshal(map[string]string{"error": "Incorrect email or password"})
				w.Write(dat)
				return
			}
			log.Printf("error getting user from database: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
			w.Write(dat)
			return
		}

		// Compare the provided password with the hashed password in the database
		match, err := auth.ComparePasswordHash(lr.Password, user.HashedPassword)
		if err != nil {
			log.Printf("error comparing password hash: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			dat, _ := json.Marshal(map[string]string{"error": "Incorrect email or password"})
			w.Write(dat)
			return
		}
		if !match {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			dat, _ := json.Marshal(map[string]string{"error": "Incorrect email or password"})
			w.Write(dat)
			return
		}

		// If the email and password are valid, respond with a 200 status code and a JSON response without the password
		resp := loginResponse{
			ID:        user.ID.String(),
			Email:     user.Email,
			CreatedAt: user.CreatedAt.UTC().Format(time.RFC3339),
			UpdatedAt: user.UpdatedAt.UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)

	})

	// Use the server ListenAndServe method to start the server
	log.Println("Starting server on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}

}

// Create struct that will hold memory data we need to keep track of

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	// add a field to story PLATFORM environment variable
	platform string
}

// Create a middleware method on the apiConfig struct that increments the fileserverHits counter every time it's called
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == "/app/" || r.URL.Path == "/app") {
			cfg.fileserverHits.Add(1)
		}
		next.ServeHTTP(w, r)
		log.Printf("File server has been hit %d times", cfg.fileserverHits.Load())
	})
}

// Add a handler for the /metrics endpoint that returns the number of times the file server has been hit with format Hits: <number>
func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	//log.Println("metricsHandler called") // Add this line
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hitCount := cfg.fileserverHits.Load()
	html := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", hitCount)
	w.Write([]byte(html))
	//log.Printf("Hit count: %d", hitCount) // Add this line

	//log.Println("metricsHandler completed") // Add this line
}

// Create /reset handler that resets the fileserverHits counter to 0
func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	//debugging logs *****
	log.Println("POST /admin/reset start")
	defer log.Println("POST /admin/reset end")

	// if not dev -> 403 JSON error, return
	if cfg.platform != "dev" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"})
		return
	}

	// call cfg.dbQueries.DeleteAllUsers(r.Context()), handle error 500
	log.Println("calling DeleteAllUsers")
	if err := cfg.dbQueries.DeleteAllUsers(r.Context()); err != nil {
		log.Printf("DeleteAllUsers error: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Something went wrong"})
		return
	}

	// reset fileserverHits to 0
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

}

// Add POST /api/chirps handler that accepts JSON body with "body" field, if chirp is valid save to database with id, created_at, updated_at, body, user_id (use any valid user_id from users table). Return 201 with JSON response containing chirp data. If invalid return 400 with JSON error message.

// methodNotAllowed responds with a 405 Method Not Allowed status code
func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// writeJSON is a helper function to write JSON responses
// go
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
