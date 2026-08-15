// Reference: Rust + Axum + sqlx + PostgreSQL
// This shows the complete auth implementation pattern for Rust.

// --- Cargo.toml dependencies ---
// axum = "0.8"
// sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "uuid", "chrono"] }
// argon2 = "0.5"
// uuid = { version = "1", features = ["v4"] }
// chrono = { version = "0.4", features = ["serde"] }
// serde = { version = "1", features = ["derive"] }
// serde_json = "1"
// rand = "0.8"
// hex = "0.4"
// sha2 = "0.10"
// tokio = { version = "1", features = ["full"] }

use axum::{
    extract::{ConnectInfo, Json, State},
    http::{header::CACHE_CONTROL, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;

// --- models ---

#[derive(sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// One table serves both flows; `purpose` keeps them apart and is matched at redemption, or
// a reset link is redeemable as an email confirmation. Only the SHA-256 of the token is
// stored — the raw value exists solely inside the emailed link. `email` records the address
// the token was issued for, so an address changed afterwards cannot inherit the proof.
#[derive(sqlx::FromRow)]
pub struct VerificationToken {
    pub id: String,
    pub user_id: String,
    pub purpose: String,
    pub email: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            email: u.email,
            name: u.name,
        }
    }
}

// --- request/response types ---

#[derive(Deserialize)]
pub struct SignUpRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Deserialize)]
pub struct SignInRequest {
    pub email: String,
    pub password: String,
}

// Both mail-sending routes take the address alone and answer identically whether or not it
// has an account, so there is nothing to distinguish their request shapes either.
#[derive(Deserialize)]
pub struct VerifyEmailSendRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct VerifyEmailConfirmRequest {
    pub token: String,
}

#[derive(Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct PasswordResetConfirmRequest {
    pub token: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub user: UserResponse,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

// --- helpers ---

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

const SESSION_DURATION_DAYS: i64 = 7;

const PURPOSE_VERIFY_EMAIL: &str = "verify-email";
const PURPOSE_PASSWORD_RESET: &str = "password-reset";
const VERIFY_EMAIL_DURATION_HOURS: i64 = 24;
const PASSWORD_RESET_DURATION_MINUTES: i64 = 30;

// Drops the address's outstanding tokens for this purpose and issues one fresh 32-byte
// token. Only its SHA-256 is stored; the raw value is returned to the caller, goes straight
// into the emailed link, and is never written down.
async fn issue_verification_token(
    pool: &PgPool,
    user_id: &str,
    email: &str,
    purpose: &str,
    ttl: Duration,
) -> Result<String, sqlx::Error> {
    sqlx::query("DELETE FROM verification_tokens WHERE user_id = $1 AND purpose = $2")
        .bind(user_id).bind(purpose)
        .execute(pool).await?;

    let raw_token = generate_token();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO verification_tokens (id, user_id, purpose, email, token_hash, expires_at, consumed_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7)"
    )
    .bind(Uuid::new_v4().to_string()).bind(user_id).bind(purpose).bind(email)
    .bind(hash_token(&raw_token)).bind(now + ttl).bind(now)
    .execute(pool).await?;

    Ok(raw_token)
}

// Delivers the raw token to the mailbox that must prove it owns the address.
//
// There is no mail transport in this reference. Replace the last line with whatever the
// project already sends mail through (SES, Postmark, an SMTP client); until that is wired
// the links never leave the process, and no deployment should print a live token.
fn send_verification_link(email: &str, purpose: &str, raw_token: &str) {
    let base_url = std::env::var("APP_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let path = match purpose {
        PURPOSE_PASSWORD_RESET => "reset-password",
        _ => "verify-email",
    };
    let link = format!("{base_url}/{path}?token={raw_token}");

    // Hand `link` to the project's mail transport here. It must never be logged:
    // the raw token is only ever stored as a hash, so a log line is a live credential.
    let _ = (email, link);
}

fn error_json(status: StatusCode, msg: &str) -> impl IntoResponse {
    (status, Json(ErrorResponse { error: msg.to_string() }))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")?
        .to_str()
        .ok()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// --- router ---

pub fn auth_router() -> Router<PgPool> {
    Router::new()
        .route("/sign-up", post(sign_up))
        .route("/sign-in", post(sign_in))
        .route("/session", get(get_session))
        .route("/sign-out", post(sign_out))
        .route("/verify-email/send", post(verify_email_send))
        .route("/verify-email/confirm", post(verify_email_confirm))
        .route("/password-reset/request", post(password_reset_request))
        .route("/password-reset/confirm", post(password_reset_confirm))
}

// --- handlers ---

async fn sign_up(
    State(pool): State<PgPool>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SignUpRequest>,
) -> impl IntoResponse {
    // Normalize email so lookups and uniqueness are case-insensitive
    let email = req.email.trim().to_lowercase();
    if email.is_empty() || req.password.len() < 8 {
        return error_json(StatusCode::BAD_REQUEST, "invalid email or password (min 8 chars)").into_response();
    }

    // Always hash password to prevent timing-based email enumeration
    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(_) => return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    let user_id = Uuid::new_v4().to_string();
    let token = generate_token();
    let now = Utc::now();
    let expires_at = now + Duration::days(SESSION_DURATION_DAYS);

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    let insert_result = sqlx::query(
        "INSERT INTO users (id, email, name, email_verified, created_at, updated_at) VALUES ($1, $2, $3, false, $4, $4)"
    )
    .bind(&user_id).bind(&email).bind(&req.name).bind(now)
    .execute(&mut *tx).await;

    if let Err(e) = insert_result {
        // Unique constraint violation (duplicate email) — return fake success
        // to prevent email enumeration. The dummy token won't resolve to a session.
        let msg = e.to_string();
        if msg.contains("unique") || msg.contains("duplicate") {
            return Json(AuthResponse {
                user: UserResponse { id: Uuid::new_v4().to_string(), email, name: req.name },
                token: generate_token(),
            }).into_response();
        }
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    // account_id for the credential provider is the user's own id.
    // The accounts table is UNIQUE on (provider_id, account_id).
    let _ = sqlx::query(
        "INSERT INTO accounts (id, user_id, account_id, provider_id, password_hash, created_at, updated_at) VALUES ($1, $2, $3, 'credential', $4, $5, $5)"
    )
    .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&user_id).bind(&password_hash).bind(now)
    .execute(&mut *tx).await;

    // IP from the peer socket address (requires `into_make_service_with_connect_info`
    // when serving); use X-Forwarded-For instead only when deployed behind a trusted proxy
    let ip_address = addr.ip().to_string();
    let user_agent = extract_user_agent(&headers);

    let _ = sqlx::query(
        "INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&token)
    .bind(&ip_address).bind(&user_agent).bind(expires_at).bind(now)
    .execute(&mut *tx).await;

    if tx.commit().await.is_err() {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    // Nothing else in a password-only build ever sets email_verified, and a row that proves
    // no identifier gets reaped, so the confirmation link goes out on every sign-up. Issued
    // after the commit: a mail failure must not undo a created account, and the user can ask
    // for another link from /verify-email/send.
    if let Ok(raw_token) = issue_verification_token(
        &pool, &user_id, &email, PURPOSE_VERIFY_EMAIL, Duration::hours(VERIFY_EMAIL_DURATION_HOURS),
    ).await {
        send_verification_link(&email, PURPOSE_VERIFY_EMAIL, &raw_token);
    }

    Json(AuthResponse {
        user: UserResponse { id: user_id, email, name: req.name },
        token,
    }).into_response()
}

async fn sign_in(
    State(pool): State<PgPool>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SignInRequest>,
) -> impl IntoResponse {
    let email = req.email.trim().to_lowercase();
    let row = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT u.id, u.email, u.name, a.password_hash FROM users u JOIN accounts a ON a.user_id = u.id WHERE u.email = $1 AND a.provider_id = 'credential'"
    )
    .bind(&email)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None);

    let Some((user_id, email, name, Some(password_hash))) = row else {
        return error_json(StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    };

    if !verify_password(&req.password, &password_hash) {
        return error_json(StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }

    let token = generate_token();
    let now = Utc::now();
    let ip_address = addr.ip().to_string();
    let user_agent = extract_user_agent(&headers);
    let _ = sqlx::query(
        "INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)"
    )
    .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&token)
    .bind(&ip_address).bind(&user_agent)
    .bind(now + Duration::days(SESSION_DURATION_DAYS)).bind(now)
    .execute(&pool).await;

    Json(AuthResponse {
        user: UserResponse { id: user_id, email, name },
        token,
    }).into_response()
}

// Every branch below builds its own response, so the header is applied once to whatever
// comes back — the 401 included. Without it the browser disk-caches this GET and keeps
// replaying "signed in" with a stale profile after the session has expired server-side.
async fn get_session(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut res = read_session(pool, headers).await;
    res.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

async fn read_session(pool: PgPool, headers: HeaderMap) -> Response {
    let Some(token) = extract_bearer_token(&headers) else {
        return error_json(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };

    let row = sqlx::query_as::<_, (String, String, Option<String>, DateTime<Utc>)>(
        "SELECT u.id, u.email, u.name, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1"
    )
    .bind(&token)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None);

    let Some((user_id, email, name, expires_at)) = row else {
        return error_json(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };

    if expires_at < Utc::now() {
        return error_json(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    Json(SessionResponse {
        user: UserResponse { id: user_id, email, name },
        expires_at,
    }).into_response()
}

async fn sign_out(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(token) = extract_bearer_token(&headers) {
        let _ = sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(&token)
            .execute(&pool)
            .await;
    }
    Json(serde_json::json!({"success": true}))
}

// Sign-up calls the same issuance path internally; this route exists for resends.
// Rate limit it per address and per IP (3 per hour is reasonable) — it sends mail on demand.
async fn verify_email_send(
    State(pool): State<PgPool>,
    Json(req): Json<VerifyEmailSendRequest>,
) -> impl IntoResponse {
    let email = req.email.trim().to_lowercase();

    let row = sqlx::query_as::<_, (String,)>("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    if let Some((user_id,)) = row {
        if let Ok(raw_token) = issue_verification_token(
            &pool, &user_id, &email, PURPOSE_VERIFY_EMAIL, Duration::hours(VERIFY_EMAIL_DURATION_HOURS),
        ).await {
            send_verification_link(&email, PURPOSE_VERIFY_EMAIL, &raw_token);
        }
    }

    // Always 200, with the same body whether or not the address has an account — this
    // endpoint must not reveal which addresses are registered.
    Json(SuccessResponse { success: true }).into_response()
}

async fn verify_email_confirm(
    State(pool): State<PgPool>,
    Json(req): Json<VerifyEmailConfirmRequest>,
) -> impl IntoResponse {
    // Look the token up by its hash, and match the purpose so a password-reset link cannot
    // be redeemed here. Consuming is one conditional write gated on consumed_at IS NULL:
    // find-then-update lets two concurrent requests both redeem the same link. A row comes
    // back only for the request that won the write.
    let consumed = sqlx::query_as::<_, (String, String)>(
        "UPDATE verification_tokens SET consumed_at = now() WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now() RETURNING user_id, email"
    )
    .bind(hash_token(&req.token)).bind(PURPOSE_VERIFY_EMAIL)
    .fetch_optional(&pool)
    .await
    .unwrap_or(None);

    let Some((user_id, email)) = consumed else {
        return error_json(StatusCode::BAD_REQUEST, "invalid or expired token").into_response();
    };

    // Bind the address the token was issued for: the proof is about that address, not about
    // whatever the row says now. email_verified stays *out* of this guard — the write records
    // a proof and authorizes nothing, so two honest confirmations must not collide. Zero rows
    // means the address changed after the link went out: discard the proof.
    let updated = sqlx::query("UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1 AND email = $2")
        .bind(&user_id).bind(&email)
        .execute(&pool)
        .await;

    // No credential strip here. This link was issued by the very sign-up that set the
    // password, so it confirms that password rather than adopting a stranger's — unlike a
    // magic link, which anyone may request for any address.
    match updated {
        Ok(res) if res.rows_affected() == 1 => Json(SuccessResponse { success: true }).into_response(),
        Ok(_) => error_json(StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(_) => error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    }
}

// Same contract as /verify-email/send: always 200, rate limit per address and per IP.
async fn password_reset_request(
    State(pool): State<PgPool>,
    Json(req): Json<PasswordResetRequest>,
) -> impl IntoResponse {
    let email = req.email.trim().to_lowercase();

    let row = sqlx::query_as::<_, (String,)>("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

    if let Some((user_id,)) = row {
        if let Ok(raw_token) = issue_verification_token(
            &pool, &user_id, &email, PURPOSE_PASSWORD_RESET, Duration::minutes(PASSWORD_RESET_DURATION_MINUTES),
        ).await {
            send_verification_link(&email, PURPOSE_PASSWORD_RESET, &raw_token);
        }
    }

    Json(SuccessResponse { success: true }).into_response()
}

async fn password_reset_confirm(
    State(pool): State<PgPool>,
    Json(req): Json<PasswordResetConfirmRequest>,
) -> impl IntoResponse {
    // Validate and hash the new password *before* the token is touched. Only failures after
    // the consume are unrecoverable, and a too-short password must not burn the link.
    if req.password.len() < 8 {
        return error_json(StatusCode::BAD_REQUEST, "invalid password (min 8 chars)").into_response();
    }
    let password_hash = match hash_password(&req.password) {
        Ok(h) => h,
        Err(_) => return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    // Same atomic consume as /verify-email/confirm, with the purpose pinned to this flow so
    // a confirmation link cannot be spent as a reset.
    let consumed = sqlx::query_as::<_, (String, String)>(
        "UPDATE verification_tokens SET consumed_at = now() WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > now() RETURNING user_id, email"
    )
    .bind(hash_token(&req.token)).bind(PURPOSE_PASSWORD_RESET)
    .fetch_optional(&mut *tx)
    .await
    .unwrap_or(None);

    let Some((user_id, email)) = consumed else {
        return error_json(StatusCode::BAD_REQUEST, "invalid or expired token").into_response();
    };

    // If the row was never verified, this reset is the first proof of mailbox control it has
    // ever had. email_verified *is* in this guard — winning the flip is what authorizes the
    // strip below, and a row that is already verified must never be stripped because its
    // credentials belong to the owner who proved it. The address is bound too, exactly as in
    // /verify-email/confirm.
    let claimed = sqlx::query("UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1 AND email = $2 AND email_verified = false")
        .bind(&user_id).bind(&email)
        .execute(&mut *tx)
        .await;
    let claimed_rows = match claimed {
        Ok(res) => res.rows_affected(),
        Err(_) => return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response(),
    };

    let now = Utc::now();
    if claimed_rows == 1 {
        // Everything this row carried predates the proof and is therefore unproven — the
        // password a planter may have set, a passkey, a linked account. Delete the rows
        // rather than blanking the hash, then write the new password into a fresh credential
        // account. All in this transaction, so no caller ever sees a verified row still
        // holding credentials that predate the proof.
        let _ = sqlx::query("DELETE FROM accounts WHERE user_id = $1")
            .bind(&user_id)
            .execute(&mut *tx).await;

        let _ = sqlx::query(
            "INSERT INTO accounts (id, user_id, account_id, provider_id, password_hash, created_at, updated_at) VALUES ($1, $2, $2, 'credential', $3, $4, $4)"
        )
        .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&password_hash).bind(now)
        .execute(&mut *tx).await;
    } else {
        // Nothing flipped, which is three different outcomes. Already verified: nothing
        // predates this proof, so keep the credentials and replace the hash in place. Row
        // gone, or re-addressed mid-flight: the proof says nothing about it, so mint nothing
        // and answer with the same generic error.
        let row = sqlx::query_as::<_, (bool,)>("SELECT email_verified FROM users WHERE id = $1 AND email = $2")
            .bind(&user_id).bind(&email)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);

        match row {
            Some((true,)) => {}
            // Commit before returning rather than dropping `tx`: the token was consumed
            // inside this transaction and a spent link is never revived, even though the
            // reset itself changes nothing.
            _ => {
                let _ = tx.commit().await;
                return error_json(StatusCode::BAD_REQUEST, "invalid or expired token").into_response();
            }
        }

        // The upsert also covers a verified row that carries no credential account yet (an
        // OAuth-only sign-up asking for a password); the proven mailbox is what authorizes
        // creating one. accounts is UNIQUE on (provider_id, account_id).
        let _ = sqlx::query(
            "INSERT INTO accounts (id, user_id, account_id, provider_id, password_hash, created_at, updated_at) VALUES ($1, $2, $2, 'credential', $3, $4, $4) ON CONFLICT (provider_id, account_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = EXCLUDED.updated_at"
        )
        .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&password_hash).bind(now)
        .execute(&mut *tx).await;
    }

    // A reset is the remedy for a compromised account, so the attacker's session must not
    // survive it. Every session goes, and none is minted — the user signs in again.
    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(&user_id)
        .execute(&mut *tx).await;

    if tx.commit().await.is_err() {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    Json(SuccessResponse { success: true }).into_response()
}
