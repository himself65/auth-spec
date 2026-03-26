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
// tokio = { version = "1", features = ["full"] }

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

// --- models ---

#[derive(sqlx::FromRow, Serialize, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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

const SESSION_DURATION_DAYS: i64 = 7;

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

// --- router ---

pub fn auth_router() -> Router<PgPool> {
    Router::new()
        .route("/sign-up", post(sign_up))
        .route("/sign-in", post(sign_in))
        .route("/session", get(get_session))
        .route("/sign-out", post(sign_out))
}

// --- handlers ---

async fn sign_up(
    State(pool): State<PgPool>,
    Json(req): Json<SignUpRequest>,
) -> impl IntoResponse {
    if req.email.is_empty() || req.password.len() < 8 {
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
    .bind(&user_id).bind(&req.email).bind(&req.name).bind(now)
    .execute(&mut *tx).await;

    if let Err(e) = insert_result {
        // Unique constraint violation (duplicate email) — return fake success
        // to prevent email enumeration. The dummy token won't resolve to a session.
        let msg = e.to_string();
        if msg.contains("unique") || msg.contains("duplicate") {
            return Json(AuthResponse {
                user: UserResponse { id: Uuid::new_v4().to_string(), email: req.email, name: req.name },
                token: generate_token(),
            }).into_response();
        }
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    let _ = sqlx::query(
        "INSERT INTO accounts (id, user_id, provider_id, password_hash, created_at, updated_at) VALUES ($1, $2, 'credential', $3, $4, $4)"
    )
    .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&password_hash).bind(now)
    .execute(&mut *tx).await;

    let _ = sqlx::query(
        "INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&token).bind(expires_at).bind(now)
    .execute(&mut *tx).await;

    if tx.commit().await.is_err() {
        return error_json(StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    }

    Json(AuthResponse {
        user: UserResponse { id: user_id, email: req.email, name: req.name },
        token,
    }).into_response()
}

async fn sign_in(
    State(pool): State<PgPool>,
    Json(req): Json<SignInRequest>,
) -> impl IntoResponse {
    let row = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "SELECT u.id, u.email, u.name, a.password_hash FROM users u JOIN accounts a ON a.user_id = u.id WHERE u.email = $1 AND a.provider_id = 'credential'"
    )
    .bind(&req.email)
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
    let _ = sqlx::query(
        "INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(Uuid::new_v4().to_string()).bind(&user_id).bind(&token)
    .bind(now + Duration::days(SESSION_DURATION_DAYS)).bind(now)
    .execute(&pool).await;

    Json(AuthResponse {
        user: UserResponse { id: user_id, email, name },
        token,
    }).into_response()
}

async fn get_session(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> impl IntoResponse {
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
