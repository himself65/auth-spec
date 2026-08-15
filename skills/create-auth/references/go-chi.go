// Reference: Go + Chi router + PostgreSQL (database/sql + pgx)
// This shows the complete auth implementation pattern for Go.

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
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
	Image         *string   `json:"image,omitempty"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IPAddress *string   `json:"ip_address,omitempty"`
	UserAgent *string   `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Account rows are unique on (provider_id, account_id).
type Account struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	ProviderID   string    `json:"provider_id"`
	AccountID    string    `json:"account_id"`
	PasswordHash *string   `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// VerificationToken rows are unique on token_hash. One table serves both flows;
// purpose keeps them apart and must be matched at redemption, or a reset link is
// redeemable as an email confirmation. Only the SHA-256 of the raw token is
// stored — the raw token exists solely inside the emailed link. Email records
// what the token proves, so a later address change cannot inherit the proof.
type VerificationToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Purpose    string     `json:"purpose"`
	Email      string     `json:"email"`
	TokenHash  string     `json:"-"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

const (
	purposeVerifyEmail   = "verify-email"
	purposePasswordReset = "password-reset"
)

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

type VerifyEmailSendRequest struct {
	Email string `json:"email"`
}

type VerifyEmailConfirmRequest struct {
	Token string `json:"token"`
}

type PasswordResetRequest struct {
	Email string `json:"email"`
}

type PasswordResetConfirmRequest struct {
	Token    string `json:"token"`
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
	r.Post("/verify-email/send", h.SendVerifyEmail)
	r.Post("/verify-email/confirm", h.ConfirmVerifyEmail)
	r.Post("/password-reset/request", h.RequestPasswordReset)
	r.Post("/password-reset/confirm", h.ConfirmPasswordReset)
	return r
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// hashToken produces the only form of a verification token that ever reaches the
// database. Lookups go by this hash; the raw token lives in the emailed link.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// execer is satisfied by both *sql.DB and *sql.Tx, so a token can be issued on
// its own connection or inside sign-up's transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// issueVerificationToken drops the user's outstanding tokens for this purpose,
// stores a fresh one by hash, and returns the raw value for the emailed link.
func issueVerificationToken(ctx context.Context, db execer, userID, purpose, email string, ttl time.Duration) (string, error) {
	if _, err := db.ExecContext(ctx,
		"DELETE FROM verification_tokens WHERE user_id = $1 AND purpose = $2",
		userID, purpose,
	); err != nil {
		return "", err
	}

	raw := generateToken()
	now := time.Now()
	if _, err := db.ExecContext(ctx,
		"INSERT INTO verification_tokens (id, user_id, purpose, email, token_hash, expires_at, consumed_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7)",
		uuid.New().String(), userID, purpose, email, hashToken(raw), now.Add(ttl), now,
	); err != nil {
		return "", err
	}
	return raw, nil
}

// sendVerificationEmail mails the link carrying the raw token. This reference
// ships no mail transport — wire a real one in here, since the raw token is
// stored nowhere and this is the only path by which it can reach the user.
// Delivery is deliberately fire-and-forget: the send endpoints answer the same
// way whether or not the address has an account, so a transport failure must
// not change the response.
func sendVerificationEmail(email, purpose, rawToken string) {
}

// clientIP returns the request's remote IP with the port stripped.
// When deployed behind a trusted proxy, use the X-Forwarded-For header instead.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

const sessionDuration = 7 * 24 * time.Hour

const (
	verifyEmailTokenDuration   = 24 * time.Hour
	passwordResetTokenDuration = 30 * time.Minute
)

func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Normalize email before validation and storage
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

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
	// For the credential provider, account_id is the new user's id ($2)
	_, err = tx.ExecContext(r.Context(),
		"INSERT INTO accounts (id, user_id, provider_id, account_id, password_hash, created_at, updated_at) VALUES ($1, $2, 'credential', $2, $3, $4, $4)",
		uuid.New().String(), userID, hashStr, now,
	)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	_, err = tx.ExecContext(r.Context(),
		"INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		uuid.New().String(), userID, token, now.Add(sessionDuration), clientIP(r), r.UserAgent(), now,
	)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Nothing else in a password-only build ever sets email_verified, and a row
	// that proves no identifier is reaped — so sign-up issues the link itself.
	verifyToken, err := issueVerificationToken(r.Context(), tx, userID, purposeVerifyEmail, req.Email, verifyEmailTokenDuration)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	sendVerificationEmail(req.Email, purposeVerifyEmail, verifyToken)

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

	// Normalize email before lookup
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	var user User
	var passwordHash sql.NullString
	err := h.db.QueryRowContext(r.Context(),
		`SELECT u.id, u.email, u.name, u.image, u.email_verified, u.created_at, u.updated_at, a.password_hash
		 FROM users u JOIN accounts a ON a.user_id = u.id
		 WHERE u.email = $1 AND a.provider_id = 'credential'`, req.Email,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Image, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt, &passwordHash)
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
		"INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		uuid.New().String(), user.ID, token, now.Add(sessionDuration), clientIP(r), r.UserAgent(), now,
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
		`SELECT u.id, u.email, u.name, u.image, u.email_verified, u.created_at, u.updated_at, s.expires_at
		 FROM sessions s JOIN users u ON u.id = s.user_id
		 WHERE s.token = $1`, token,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Image, &user.EmailVerified, &user.CreatedAt, &user.UpdatedAt, &expiresAt)
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

// SendVerifyEmail re-sends the confirmation link. Sign-up issues the first one
// inline; this route exists for resends. Rate limit it per address and per IP
// (3 per hour is reasonable) — it sends mail on demand.
func (h *AuthHandler) SendVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailSendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Normalize email before lookup
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	// Every branch below ends in the same 200: a response that varied with the
	// lookup would turn this endpoint into an account-existence oracle. A failure
	// to issue or send is swallowed for the same reason.
	var userID string
	var emailVerified bool
	err := h.db.QueryRowContext(r.Context(),
		"SELECT id, email_verified FROM users WHERE email = $1", req.Email,
	).Scan(&userID, &emailVerified)
	if err == nil && !emailVerified {
		if raw, err := issueVerificationToken(r.Context(), h.db, userID, purposeVerifyEmail, req.Email, verifyEmailTokenDuration); err == nil {
			sendVerificationEmail(req.Email, purposeVerifyEmail, raw)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

func (h *AuthHandler) ConfirmVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req VerifyEmailConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Token == "" {
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusBadRequest)
		return
	}

	// Consume atomically: one conditional write gated on consumed_at IS NULL,
	// never find-then-update. RETURNING hands back the row only to the request
	// that won the write. purpose is matched here so a password-reset link can
	// never be redeemed as an email confirmation.
	var userID, email string
	err := h.db.QueryRowContext(r.Context(),
		`UPDATE verification_tokens SET consumed_at = now()
		 WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
		 RETURNING user_id, email`,
		hashToken(req.Token), purposeVerifyEmail,
	).Scan(&userID, &email)
	if err != nil {
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusBadRequest)
		return
	}

	// This write records a proof and authorizes nothing, so it names the address
	// the token was issued for and keeps email_verified itself out of the guard.
	// Zero rows means the address changed after the link was mailed: the proof is
	// about an address this row no longer holds, so discard it.
	//
	// No credential strip here, unlike a magic link: this link was issued by the
	// very sign-up that set the password, so it confirms that password rather
	// than adopting a stranger's.
	res, err := h.db.ExecContext(r.Context(),
		"UPDATE users SET email_verified = true WHERE id = $1 AND email = $2",
		userID, email,
	)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

// RequestPasswordReset mails a reset link. Same contract as SendVerifyEmail:
// always 200, and rate limited per address and per IP.
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Normalize email before lookup
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	var userID string
	err := h.db.QueryRowContext(r.Context(),
		"SELECT id FROM users WHERE email = $1", req.Email,
	).Scan(&userID)
	if err == nil {
		if raw, err := issueVerificationToken(r.Context(), h.db, userID, purposePasswordReset, req.Email, passwordResetTokenDuration); err == nil {
			sendVerificationEmail(req.Email, purposePasswordReset, raw)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

func (h *AuthHandler) ConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req PasswordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate and hash the new password before the token is touched — a rejected
	// password must not burn the link. Only failures after the consume are
	// unrecoverable.
	if req.Token == "" || len(req.Password) < 8 {
		http.Error(w, `{"error":"invalid token or password (min 8 chars)"}`, http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Consume atomically, with purpose matched so a confirm-your-email link
	// cannot be spent here.
	var userID, email string
	err = tx.QueryRowContext(r.Context(),
		`UPDATE verification_tokens SET consumed_at = now()
		 WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
		 RETURNING user_id, email`,
		hashToken(req.Token), purposePasswordReset,
	).Scan(&userID, &email)
	if err != nil {
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusBadRequest)
		return
	}

	now := time.Now()
	hashStr := string(hash)

	// Claim the row if it has never proven mailbox control. email_verified belongs
	// in *this* guard — winning the flip is what authorizes the strip below, and
	// it encodes the condition that an already-verified row must never be
	// stripped. The address is bound too, or a change racing the mail round trip
	// would inherit a proof never made about it.
	var claimedID string
	err = tx.QueryRowContext(r.Context(),
		"UPDATE users SET email_verified = true WHERE id = $1 AND email = $2 AND email_verified = false RETURNING id",
		userID, email,
	).Scan(&claimedID)
	switch {
	case err == nil:
		// This reset is the first proof of mailbox control the row has ever had,
		// so everything it carries predates that proof and is unproven — a planted
		// password, a planted passkey, a linked OAuth account. Delete the rows
		// rather than blanking the hash, then write the new password into a fresh
		// credential account.
		if _, err := tx.ExecContext(r.Context(), "DELETE FROM accounts WHERE user_id = $1", userID); err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		if _, err := tx.ExecContext(r.Context(),
			"INSERT INTO accounts (id, user_id, provider_id, account_id, password_hash, created_at, updated_at) VALUES ($1, $2, 'credential', $2, $3, $4, $4)",
			uuid.New().String(), userID, hashStr, now,
		); err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
	case errors.Is(err, sql.ErrNoRows):
		// Nothing flipped, and the three reasons are not the same outcome. Re-read
		// under the same guard minus the flag: if the row is gone or now holds a
		// different address, the proof says nothing about it — change nothing.
		var emailVerified bool
		if err := tx.QueryRowContext(r.Context(),
			"SELECT email_verified FROM users WHERE id = $1 AND email = $2", userID, email,
		).Scan(&emailVerified); err != nil || !emailVerified {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusBadRequest)
			return
		}
		// Already verified: its credentials belong to the owner who proved it, so
		// update the existing credential account in place. A build where a verified
		// row may hold no credential account — passkey-only, OAuth-only — inserts
		// one here instead of treating zero rows as an error.
		res, err := tx.ExecContext(r.Context(),
			"UPDATE accounts SET password_hash = $1, updated_at = $2 WHERE user_id = $3 AND provider_id = 'credential' AND account_id = $3",
			hashStr, now, userID,
		)
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		n, err := res.RowsAffected()
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		if n == 0 {
			// Verified but holding no credential account (passkey-only, OAuth-only):
			// create one rather than failing the reset.
			if _, err := tx.ExecContext(r.Context(),
				"INSERT INTO accounts (id, user_id, provider_id, account_id, password_hash, created_at, updated_at) VALUES ($1, $2, 'credential', $2, $3, $4, $4)",
				uuid.New().String(), userID, hashStr, now,
			); err != nil {
				http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
				return
			}
		}
	default:
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// A reset is the remedy for a compromised account, so every session dies with
	// it — the attacker's included. No new one is minted: require a fresh sign-in.
	if _, err := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE user_id = $1", userID); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}
