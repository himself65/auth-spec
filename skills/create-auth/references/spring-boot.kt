// Reference: Kotlin + Spring Boot + Spring Data JPA + PostgreSQL
// This shows the complete auth implementation pattern for Spring Boot.

// --- build.gradle.kts dependencies ---
// implementation("org.springframework.boot:spring-boot-starter-web")
// implementation("org.springframework.boot:spring-boot-starter-data-jpa")
// implementation("org.springframework.security:spring-security-crypto")
// runtimeOnly("org.postgresql:postgresql")

package com.example.auth

import jakarta.persistence.*
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

// --- entities ---

@Entity
@Table(name = "users")
data class User(
    @Id val id: String = UUID.randomUUID().toString(),
    @Column(unique = true, nullable = false) val email: String = "",
    val name: String? = null,
    @Column(name = "email_verified") val emailVerified: Boolean = false,
    @Column(name = "created_at") val createdAt: Instant = Instant.now(),
    @Column(name = "updated_at") var updatedAt: Instant = Instant.now(),
)

@Entity
@Table(name = "sessions")
data class Session(
    @Id val id: String = UUID.randomUUID().toString(),
    @Column(name = "user_id", nullable = false) val userId: String = "",
    @Column(unique = true, nullable = false) val token: String = "",
    @Column(name = "expires_at", nullable = false) val expiresAt: Instant = Instant.now(),
    @Column(name = "created_at") val createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "accounts")
data class Account(
    @Id val id: String = UUID.randomUUID().toString(),
    @Column(name = "user_id", nullable = false) val userId: String = "",
    @Column(name = "provider_id", nullable = false) val providerId: String = "",
    @Column(name = "password_hash") val passwordHash: String? = null,
    @Column(name = "created_at") val createdAt: Instant = Instant.now(),
    @Column(name = "updated_at") var updatedAt: Instant = Instant.now(),
)

// --- repositories ---

interface UserRepository : JpaRepository<User, String> {
    fun findByEmail(email: String): User?
}

interface SessionRepository : JpaRepository<Session, String> {
    fun findByToken(token: String): Session?
    fun deleteByToken(token: String)
}

interface AccountRepository : JpaRepository<Account, String> {
    fun findByUserIdAndProviderId(userId: String, providerId: String): Account?
}

// --- DTOs ---

data class SignUpRequest(val email: String, val password: String, val name: String? = null)
data class SignInRequest(val email: String, val password: String)
data class UserResponse(val id: String, val email: String, val name: String?)
data class AuthResponse(val user: UserResponse, val token: String)
data class SessionResponse(val user: UserResponse, val expiresAt: Instant)

// --- controller ---

@RestController
@RequestMapping("/api/auth")
class AuthController(
    private val userRepo: UserRepository,
    private val sessionRepo: SessionRepository,
    private val accountRepo: AccountRepository,
) {
    private val encoder = BCryptPasswordEncoder(12)
    private val sessionDuration = 7L // days

    private fun generateToken(): String = UUID.randomUUID().toString() + UUID.randomUUID().toString()

    @PostMapping("/sign-up")
    fun signUp(@RequestBody req: SignUpRequest): ResponseEntity<AuthResponse> {
        if (req.email.isBlank() || req.password.length < 8) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email or password (min 8 chars)")
        }

        // Always hash password to prevent timing-based email enumeration
        val passwordHash = encoder.encode(req.password)

        try {
            val user = userRepo.save(User(email = req.email, name = req.name))

            accountRepo.save(Account(
                userId = user.id,
                providerId = "credential",
                passwordHash = passwordHash,
            ))

            val token = generateToken()
            sessionRepo.save(Session(
                userId = user.id,
                token = token,
                expiresAt = Instant.now().plus(sessionDuration, ChronoUnit.DAYS),
            ))

            return ResponseEntity.ok(AuthResponse(
                user = UserResponse(user.id, user.email, user.name),
                token = token,
            ))
        } catch (e: Exception) {
            // Unique constraint violation (duplicate email) — return fake success
            // to prevent email enumeration. The dummy token won't resolve to a session.
            return ResponseEntity.ok(AuthResponse(
                user = UserResponse(UUID.randomUUID().toString(), req.email, req.name),
                token = generateToken(),
            ))
        }
    }

    @PostMapping("/sign-in")
    fun signIn(@RequestBody req: SignInRequest): AuthResponse {
        val user = userRepo.findByEmail(req.email)
            ?: throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials")

        val account = accountRepo.findByUserIdAndProviderId(user.id, "credential")
            ?: throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials")

        if (account.passwordHash == null || !encoder.matches(req.password, account.passwordHash)) {
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials")
        }

        val token = generateToken()
        sessionRepo.save(Session(
            userId = user.id,
            token = token,
            expiresAt = Instant.now().plus(sessionDuration, ChronoUnit.DAYS),
        ))

        return AuthResponse(
            user = UserResponse(user.id, user.email, user.name),
            token = token,
        )
    }

    @GetMapping("/session")
    fun getSession(@RequestHeader("Authorization") auth: String): SessionResponse {
        val token = auth.removePrefix("Bearer ").trim()
        if (token.isBlank()) {
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")
        }

        val session = sessionRepo.findByToken(token)
            ?: throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")

        if (session.expiresAt.isBefore(Instant.now())) {
            throw ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")
        }

        val user = userRepo.findById(session.userId).orElseThrow {
            ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized")
        }

        return SessionResponse(
            user = UserResponse(user.id, user.email, user.name),
            expiresAt = session.expiresAt,
        )
    }

    @PostMapping("/sign-out")
    fun signOut(@RequestHeader("Authorization", required = false) auth: String?): Map<String, Boolean> {
        val token = auth?.removePrefix("Bearer ")?.trim()
        if (!token.isNullOrBlank()) {
            sessionRepo.deleteByToken(token)
        }
        return mapOf("success" to true)
    }
}
