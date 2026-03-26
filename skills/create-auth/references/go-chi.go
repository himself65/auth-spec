// Reference: Go + Chi router + PostgreSQL (database/sql + pgx)
// This shows the complete auth implementation pattern for Go.

package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// --- models ---

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          *string   `json:"name,omitempty"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type Account struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	ProviderID   string    `json:"provider_id"`
	PasswordHash *string   `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// --- request/response types ---

type SignUpRequest struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	Name     *string `json:"name,omitempty"`
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	User  User   `json:"user"`
	Token string `json:"token"`
}

type SessionResponse struct {
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

// --- handler ---

type AuthHandler struct {
	db *sql.DB
}

func NewAuthHandler(db *sql.DB) *AuthHandler {
	return &AuthHandler{db: db}
}

func (h *AuthHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/sign-up", h.SignUp)
	r.Post("/sign-in", h.SignIn)
	r.Get("/session", h.GetSession)
	r.Post("/sign-out", h.SignOut)
	return r
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

const sessionDuration = 7 * 24 * time.Hour

func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Email == "" || len(req.Password) < 8 {
		http.Error(w, `{"error":"invalid email or password (min 8 chars)"}`, http.StatusBadRequest)
		return
	}

	// Always hash password to prevent timing-based email enumeration
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	userID := uuid.New().String()
	token := generateToken()
	now := time.Now()

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(r.Context(),
		"INSERT INTO users (id, email, name, email_verified, created_at, updated_at) VALUES ($1, $2, $3, false, $4, $4)",
		userID, req.Email, req.Name, now,
	)
	if err != nil {
		// Unique constraint violation (duplicate email) — return fake success
		// to prevent email enumeration. The dummy token won't resolve to a session.
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(AuthResponse{
				User:  User{ID: uuid.New().String(), Email: req.Email, Name: req.Name, CreatedAt: now, UpdatedAt: now},
				Token: generateToken(),
			})
			return
		}
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	hashStr := string(hash)
	_, err = tx.ExecContext(r.Context(),
		"INSERT INTO accounts (id, user_id, provider_id, password_hash, created_at, updated_at) VALUES ($1, $2, 'credential', $3, $4, $4)",
		uuid.New().String(), userID, hashStr, now,
	)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	_, err = tx.ExecContext(r.Context(),
		"INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)",
		uuid.New().String(), userID, token, now.Add(sessionDuration), now,
	)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(AuthResponse{
		User:  User{ID: userID, Email: req.Email, Name: req.Name, CreatedAt: now, UpdatedAt: now},
		Token: token,
	})
}

func (h *AuthHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	var req SignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	var user User
	var passwordHash sql.NullString
	err := h.db.QueryRowContext(r.Context(),
		`SELECT u.id, u.email, u.name, u.email_verified, u.created_at, u.updated_at, a.password_hash
		 FROM users u JOIN accounts a ON a.user_id = u.id
		 WHERE u.email = $1 AND a.provider_id = 'credential'`, req.Email,
	).Scan(&user.ID, &user.Email, &user.Name, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt, &passwordHash)
	if err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	if !passwordHash.Valid || bcrypt.CompareHashAndPassword([]byte(passwordHash.String), []byte(req.Password)) != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token := generateToken()
	now := time.Now()
	_, err = h.db.ExecContext(r.Context(),
		"INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)",
		uuid.New().String(), user.ID, token, now.Add(sessionDuration), now,
	)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{User: user, Token: token})
}

func (h *AuthHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var user User
	var expiresAt time.Time
	err := h.db.QueryRowContext(r.Context(),
		`SELECT u.id, u.email, u.name, u.email_verified, u.created_at, u.updated_at, s.expires_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token = $1`, token,
	).Scan(&user.ID, &user.Email, &user.Name, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt, &expiresAt)
	if err != nil || expiresAt.Before(time.Now()) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SessionResponse{User: user, ExpiresAt: expiresAt})
}

func (h *AuthHandler) SignOut(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token != "" {
		h.db.ExecContext(r.Context(), "DELETE FROM sessions WHERE token = $1", token)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}
