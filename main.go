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

	"github.com/jamesboder/ChirpySocialMedia/internal/database"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

func main() {

	// call godotenv
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

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

	//mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	//w.WriteHeader(200)
	//w.Write([]byte("OK"))
	//
	//})

	// Add the /metrics endpoint to the main function that responds to GET requests only. returns HTML to be rendered in the browser

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("/admin/metrics", methodNotAllowed)

	//log.Println("Registered /metrics handler") // Add this line for debugging

	// Add the /reset endpoint to the main function
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("/admin/reset", methodNotAllowed)

	// Add a new endpoint that accepts POST requests at /api/validate_chirp. It should expect a JSON body.
	mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, r *http.Request) {
		// init struct to hold incoming JSON data
		type chirp struct {
			Body string `json:"body"`
		}

		// decode the JSON body into the chirp struct
		decoder := json.NewDecoder(r.Body)
		var c chirp
		err := decoder.Decode(&c)

		//

		if err != nil {
			log.Printf("error decoding JSON: %v", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			dat, _ := json.Marshal(map[string]string{"error": "Something went wrong"})
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
		// Respond with a 200 status code and a JSON response indicating the chirp is valid and the cleaned chirp
		// Example: {"cleaned_chirp": "This is a **** example"}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"cleaned_body": cleanedChirp,
		}
		jsonResp, _ := json.Marshal(resp)
		w.Write(jsonResp)

	})

	//mux.HandleFunc("/api/validate_chirp", methodNotAllowed)

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
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits counter reset to 0"))
}

// methodNotAllowed responds with a 405 Method Not Allowed status code
func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}
