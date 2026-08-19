// Reference: Kotlin + Spring Boot + Spring Data JPA + PostgreSQL
// This shows the complete auth implementation pattern for Spring Boot.

// --- build.gradle.kts dependencies ---
// implementation("org.springframework.boot:spring-boot-starter-web")
// implementation("org.springframework.boot:spring-boot-starter-data-jpa")
// implementation("org.springframework.security:spring-security-crypto")
// runtimeOnly("org.postgresql:postgresql")
// The kotlin("plugin.spring") plugin opens @RestController classes so the @Transactional
// handlers below can be proxied.

package com.example.auth

import jakarta.persistence.*
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.Normalizer
import java.time.Duration
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
    val image: String? = null,
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
    @Column(name = "ip_address") val ipAddress: String? = null,
    @Column(name = "user_agent") val userAgent: String? = null,
    @Column(name = "expires_at", nullable = false) val expiresAt: Instant = Instant.now(),
    @Column(name = "created_at") val createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "accounts", uniqueConstraints = [UniqueConstraint(columnNames = ["provider_id", "account_id"])])
data class Account(
    @Id val id: String = UUID.randomUUID().toString(),
    @Column(name = "user_id", nullable = false) val userId: String = "",
    @Column(name = "account_id", nullable = false) val accountId: String = "",
    @Column(name = "provider_id", nullable = false) val providerId: String = "",
    @Column(name = "password_hash") val passwordHash: String? = null,
    @Column(name = "created_at") val createdAt: Instant = Instant.now(),
    @Column(name = "updated_at") var updatedAt: Instant = Instant.now(),
)

@Entity
@Table(name = "verification_tokens")
data class VerificationToken(
    @Id val id: String = UUID.randomUUID().toString(),
    @Column(name = "user_id", nullable = false) val userId: String = "",
    // "verify-email" or "password-reset" — matched at redemption, so a reset link
    // can never be spent as an email confirmation
    @Column(nullable = false) val purpose: String = "",
    // The address the token was issued for; a later address change cannot inherit its proof
    @Column(nullable = false) val email: String = "",
    // SHA-256 of the raw token — the raw value exists only inside the emailed link
    @Column(name = "token_hash", unique = true, nullable = false) val tokenHash: String = "",
    @Column(name = "expires_at", nullable = false) val expiresAt: Instant = Instant.now(),
    @Column(name = "consumed_at") val consumedAt: Instant? = null,
    @Column(name = "created_at") val createdAt: Instant = Instant.now(),
)

// --- repositories ---

interface UserRepository : JpaRepository<User, String> {
    fun findByEmail(email: String): User?

    // Records a proof and authorizes nothing, so the guard names the address the token
    // was issued for and deliberately leaves email_verified out: two honest confirmations
    // of the same unchanged address must not conflict.
    @Modifying
    @Transactional
    @Query("update User u set u.emailVerified = true, u.updatedAt = :now where u.id = :id and u.email = :email")
    fun markEmailVerified(@Param("id") id: String, @Param("email") email: String, @Param("now") now: Instant): Int

    // Winning this flip is what authorizes the credential strip, so email_verified *is*
    // in the guard: it serializes concurrent proofs to exactly one stripper, and a row
    // that is already verified — whose credentials belong to the owner who proved it —
    // never matches.
    @Modifying
    @Transactional
    @Query("update User u set u.emailVerified = true, u.updatedAt = :now where u.id = :id and u.email = :email and u.emailVerified = false")
    fun claimUnverified(@Param("id") id: String, @Param("email") email: String, @Param("now") now: Instant): Int
}

interface SessionRepository : JpaRepository<Session, String> {
    fun findByToken(token: String): Session?
    fun deleteByToken(token: String)

    @Transactional
    fun deleteByUserId(userId: String)
}

interface AccountRepository : JpaRepository<Account, String> {
    fun findByUserIdAndProviderId(userId: String, providerId: String): Account?

    @Transactional
    fun deleteByUserId(userId: String)
}

interface VerificationTokenRepository : JpaRepository<VerificationToken, String> {
    fun findByTokenHash(tokenHash: String): VerificationToken?

    @Transactional
    fun deleteByUserIdAndPurpose(userId: String, purpose: String)

    // Consumption is one conditional write, never find-then-update: the affected-row
    // count decides the winner, so a double-submitted link is spent exactly once.
    @Modifying
    @Transactional
    @Query("update VerificationToken t set t.consumedAt = :now where t.id = :id and t.consumedAt is null and t.expiresAt > :now")
    fun consume(@Param("id") id: String, @Param("now") now: Instant): Int
}

// --- DTOs ---

data class SignUpRequest(val email: String, val password: String, val name: String? = null)
data class SignInRequest(val email: String, val password: String)
data class UserResponse(val id: String, val email: String, val name: String?)
data class AuthResponse(val user: UserResponse, val token: String)
data class SessionResponse(val user: UserResponse, val expiresAt: Instant)
data class VerifyEmailSendRequest(val email: String)
data class VerifyEmailConfirmRequest(val token: String)
data class PasswordResetRequest(val email: String)
data class PasswordResetConfirmRequest(val token: String, val password: String)
data class StatusResponse(val success: Boolean)

// --- controller ---

@RestController
@RequestMapping("/api/auth")
class AuthController(
    private val userRepo: UserRepository,
    private val sessionRepo: SessionRepository,
    private val accountRepo: AccountRepository,
    private val tokenRepo: VerificationTokenRepository,
    // Where the emailed links point; the browser routes these paths to the pages that
    // POST back to the confirm endpoints below
    @Value("\${app.base-url:http://localhost:8080}") private val baseUrl: String,
) {
    private val encoder = BCryptPasswordEncoder(12)
    private val sessionDuration = 7L // days
    private val purposeVerifyEmail = "verify-email"
    private val purposePasswordReset = "password-reset"
    private val verifyEmailTokenTtl: Duration = Duration.ofHours(24)
    private val passwordResetTokenTtl: Duration = Duration.ofMinutes(30)
    private val random = SecureRandom()

    private fun generateToken(): String = UUID.randomUUID().toString() + UUID.randomUUID().toString()

    private fun generateVerificationToken(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun hashToken(token: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(token.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    // Canonicalize before validating (CWE-180): NFKC first, so a homoglyph such as a
    // fullwidth ＠ (U+FF20) is folded before the single-@ check runs, and the string we
    // validate is the exact string we store and mail — a mailer that normalizes on its
    // own must never see something different from what we checked. Non-ASCII that
    // survives is then rejected outright: this reference does not support
    // internationalized addresses.
    private fun normalizeEmail(raw: String): String =
        Normalizer.normalize(raw, Normalizer.Form.NFKC).trim().lowercase()

    // Strict lowercase RFC 5322 dot-atom on both sides — no quotes, comments, angle
    // brackets, commas, spaces, or non-ASCII — so no mail library can re-parse the
    // string we validated into a different recipient. Exactly one "@", ≤ 254 chars.
    // Uppercase is rejected on purpose: the validator then fails closed on anything
    // that skipped normalizeEmail. IP-literal domains (`user@[127.0.0.1]`) are not
    // accepted.
    private val emailShape = Regex(
        "[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@[a-z0-9-]+(?:\\.[a-z0-9-]+)*"
    )

    private fun isValidEmail(email: String): Boolean = email.length <= 254 && emailShape.matches(email)

    // Replaces any outstanding token for this purpose and returns the raw value, which
    // is stored nowhere — only its SHA-256 reaches the database.
    private fun issueVerificationToken(user: User, purpose: String, ttl: Duration): String {
        tokenRepo.deleteByUserIdAndPurpose(user.id, purpose)
        val raw = generateVerificationToken()
        tokenRepo.save(VerificationToken(
            userId = user.id,
            purpose = purpose,
            // The address the token proves control of, captured at issue time
            email = user.email,
            tokenHash = hashToken(raw),
            expiresAt = Instant.now().plus(ttl),
        ))
        return raw
    }

    private fun verifyEmailLink(rawToken: String): String = "$baseUrl/verify-email?token=$rawToken"

    private fun passwordResetLink(rawToken: String): String = "$baseUrl/reset-password?token=$rawToken"

    // Delivery is the one side effect this reference cannot perform — there is no mail
    // transport here. Replace these two bodies with the project's own (Spring's
    // JavaMailSender, an HTTP provider client, an outbox row) and keep the raw token out
    // of logs and metrics: the emailed link is the only place it may ever appear.
    private fun sendEmailVerificationLink(email: String, link: String) {
        // Wire a real transport: "Confirm your email" carrying `link`, addressed to `email`.
    }

    private fun sendPasswordResetLink(email: String, link: String) {
        // Wire a real transport: "Reset your password" carrying `link`, addressed to `email`.
    }

    @PostMapping("/sign-up")
    fun signUp(@RequestBody req: SignUpRequest, request: HttpServletRequest): ResponseEntity<AuthResponse> {
        // Canonicalize email before validation and storage
        val email = normalizeEmail(req.email)
        if (!isValidEmail(email) || req.password.length < 8) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email or password (min 8 chars)")
        }

        // Always hash password to prevent timing-based email enumeration
        val passwordHash = encoder.encode(req.password)

        try {
            val user = userRepo.save(User(email = email, name = req.name))

            // account_id for the credential provider is the user's own id
            accountRepo.save(Account(
                userId = user.id,
                accountId = user.id,
                providerId = "credential",
                passwordHash = passwordHash,
            ))

            val token = generateToken()
            sessionRepo.save(Session(
                userId = user.id,
                token = token,
                // remoteAddr is the direct peer; use X-Forwarded-For instead only
                // when deployed behind a trusted proxy
                ipAddress = request.remoteAddr,
                userAgent = request.getHeader("User-Agent"),
                expiresAt = Instant.now().plus(sessionDuration, ChronoUnit.DAYS),
            ))

            // Nothing else in a password-only build ever sets email_verified, and a row
            // that proves no identifier is reaped — so sign-up issues the link itself.
            // Caught separately: a mail outage must not fall through to the duplicate-email
            // handler below and answer a real sign-up with the fake-success token. The
            // account already exists, and /verify-email/send reissues.
            try {
                sendEmailVerificationLink(
                    user.email,
                    verifyEmailLink(issueVerificationToken(user, purposeVerifyEmail, verifyEmailTokenTtl)),
                )
            } catch (mailFailure: Exception) {
                // Transport failure only.
            }

            return ResponseEntity.ok(AuthResponse(
                user = UserResponse(user.id, user.email, user.name),
                token = token,
            ))
        } catch (e: Exception) {
            // Unique constraint violation (duplicate email) — return fake success
            // to prevent email enumeration. The dummy token won't resolve to a session.
            return ResponseEntity.ok(AuthResponse(
                user = UserResponse(UUID.randomUUID().toString(), email, req.name),
                token = generateToken(),
            ))
        }
    }

    @PostMapping("/sign-in")
    fun signIn(@RequestBody req: SignInRequest, request: HttpServletRequest): AuthResponse {
        val email = normalizeEmail(req.email)
        val user = userRepo.findByEmail(email)
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
            ipAddress = request.remoteAddr,
            userAgent = request.getHeader("User-Agent"),
            expiresAt = Instant.now().plus(sessionDuration, ChronoUnit.DAYS),
        ))

        return AuthResponse(
            user = UserResponse(user.id, user.email, user.name),
            token = token,
        )
    }

    @GetMapping("/session")
    fun getSession(
        @RequestHeader("Authorization") auth: String,
        response: HttpServletResponse,
    ): SessionResponse {
        // Set once on the servlet response, before any branch, so it survives the
        // thrown 401 as well: this GET must never be disk-cached, or the browser keeps
        // replaying "signed in" with a stale profile after the session has expired.
        response.setHeader("Cache-Control", "no-store")

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

    @PostMapping("/verify-email/send")
    fun sendVerifyEmail(@RequestBody req: VerifyEmailSendRequest): StatusResponse {
        val email = normalizeEmail(req.email)
        val user = userRepo.findByEmail(email)

        // Rate limit this per address and per IP (3 per hour is reasonable) — it sends
        // mail on demand
        if (user != null && !user.emailVerified) {
            sendEmailVerificationLink(
                user.email,
                verifyEmailLink(issueVerificationToken(user, purposeVerifyEmail, verifyEmailTokenTtl)),
            )
        }

        // Same response whether or not the address has an account: this endpoint must
        // not reveal which addresses are registered
        return StatusResponse(true)
    }

    @PostMapping("/verify-email/confirm")
    // noRollbackFor: a thrown 4xx here must not roll the transaction back. The token is
    // consumed inside it, and a spent link is never revived — rolling back would hand an
    // attacker unlimited retries. Genuine 500-class failures still roll back.
    @Transactional(noRollbackFor = [ResponseStatusException::class])
    fun confirmVerifyEmail(@RequestBody req: VerifyEmailConfirmRequest): StatusResponse {
        val now = Instant.now()

        // Look up by hash — the raw token was never stored — and require the purpose,
        // so a password-reset link cannot be redeemed as an email confirmation
        val token = tokenRepo.findByTokenHash(hashToken(req.token))
        if (token == null || token.purpose != purposeVerifyEmail) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token")
        }

        // The read above is for data only; this write is the gate
        if (tokenRepo.consume(token.id, now) != 1) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token")
        }

        // Bind the address the link was issued for, and keep the flag itself out of the
        // guard. Zero rows means the account was re-addressed after the link went out,
        // so the proof says nothing about the address it holds now — discard it
        if (userRepo.markEmailVerified(token.userId, token.email, now) != 1) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token")
        }

        // No credential strip here: this link was issued by the very sign-up that set the
        // password, so it confirms that password rather than adopting a stranger's
        return StatusResponse(true)
    }

    @PostMapping("/password-reset/request")
    fun requestPasswordReset(@RequestBody req: PasswordResetRequest): StatusResponse {
        val email = normalizeEmail(req.email)
        val user = userRepo.findByEmail(email)

        // Rate limit per address and per IP, as with verify-email/send
        if (user != null) {
            sendPasswordResetLink(
                user.email,
                passwordResetLink(issueVerificationToken(user, purposePasswordReset, passwordResetTokenTtl)),
            )
        }

        return StatusResponse(true)
    }

    @PostMapping("/password-reset/confirm")
    // noRollbackFor: a thrown 4xx here must not roll the transaction back. The token is
    // consumed inside it, and a spent link is never revived — rolling back would hand an
    // attacker unlimited retries. Genuine 500-class failures still roll back.
    @Transactional(noRollbackFor = [ResponseStatusException::class])
    fun confirmPasswordReset(@RequestBody req: PasswordResetConfirmRequest): StatusResponse {
        // Validate before touching the token: a rejected password must not burn the link
        if (req.password.length < 8) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid password (min 8 chars)")
        }

        val now = Instant.now()

        val token = tokenRepo.findByTokenHash(hashToken(req.token))
        if (token == null || token.purpose != purposePasswordReset) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token")
        }

        if (tokenRepo.consume(token.id, now) != 1) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token")
        }

        val passwordHash = encoder.encode(req.password)

        if (userRepo.claimUnverified(token.userId, token.email, now) == 1) {
            // The row had never proved control of its address, so everything it carries is
            // unproven — a planted password, a planted passkey, a linked OAuth account.
            // Strip the credentials and write the new password into a fresh one
            accountRepo.deleteByUserId(token.userId)
            // Flush the deletes before the insert: the new credential reuses the
            // (provider_id, account_id) tuple, and Hibernate orders inserts ahead of
            // deletes within a single flush
            accountRepo.flush()
            accountRepo.save(Account(
                userId = token.userId,
                accountId = token.userId,
                providerId = "credential",
                passwordHash = passwordHash,
            ))
        } else {
            // Nothing flipped, which is three different outcomes: the row is already
            // verified — its credentials belong to the owner who proved it, so update in
            // place — or it is gone, or it now holds a different address
            val user = userRepo.findById(token.userId).orElse(null)
            if (user == null || user.email != token.email) {
                throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token")
            }

            val account = accountRepo.findByUserIdAndProviderId(user.id, "credential")
            if (account != null) {
                accountRepo.save(account.copy(passwordHash = passwordHash, updatedAt = now))
            } else {
                accountRepo.save(Account(
                    userId = user.id,
                    accountId = user.id,
                    providerId = "credential",
                    passwordHash = passwordHash,
                ))
            }
        }

        // A reset is the remedy for a compromised account, so every session dies with it
        // — the strip's sessions included — and none is minted: the user signs in again
        sessionRepo.deleteByUserId(token.userId)

        return StatusResponse(true)
    }
}
