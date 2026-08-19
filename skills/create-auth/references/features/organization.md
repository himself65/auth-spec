# Organization / Teams

Multi-tenant support with roles, invitations, and role-based access control (RBAC).

## Schema Additions

**Organization**
| Field     | Type     | Constraints      |
|-----------|----------|------------------|
| id        | string   | primary key      |
| name      | string   | not null         |
| slug      | string   | unique, not null |
| createdAt | datetime | default now      |
| updatedAt | datetime | auto-update      |

**OrganizationMember**
| Field          | Type     | Constraints                              |
|----------------|----------|------------------------------------------|
| id             | string   | primary key                              |
| organizationId | string   | foreign key -> Organization, not null    |
| userId         | string   | foreign key -> User, not null            |
| role           | string   | not null (default: "member")             |
| createdAt      | datetime | default now                              |

Unique constraint on (organizationId, userId).

**OrganizationInvitation**
| Field          | Type     | Constraints                              |
|----------------|----------|------------------------------------------|
| id             | string   | primary key                              |
| organizationId | string   | foreign key -> Organization, not null    |
| email          | string   | not null (stored in canonical form)      |
| role           | string   | not null (default: "member")             |
| tokenHash      | string   | unique, not null (SHA-256 of the raw token) |
| expiresAt      | datetime | not null (default: 7 days)               |
| createdAt      | datetime | default now                              |

**OrganizationDomain** — only if you build domain-based auto-join (see below); omit otherwise.
| Field          | Type     | Constraints                              |
|----------------|----------|------------------------------------------|
| id             | string   | primary key                              |
| organizationId | string   | foreign key -> Organization, not null    |
| domain         | string   | unique, not null (lowercased hostname; one row per domain, never a comma-delimited column) |
| challengeToken | string   | not null (crypto-random, published by the admin to prove control) |
| verifiedAt     | datetime | nullable (null = claimed but unproven)   |

## Default Roles

| Role   | Permissions                                         |
|--------|-----------------------------------------------------|
| owner  | All permissions, can delete org, transfer ownership  |
| admin  | Manage members, manage invitations, update org       |
| member | Read org, read members                               |

## Endpoints

**POST /api/auth/org**
- Requires valid session
- Body: `{ name, slug? }`
- Create organization, add creator as "owner"
- Auto-generate slug from name if not provided
- Return organization + membership

**GET /api/auth/org/:slugOrId**
- Requires valid session + membership in the org
- Return organization details + current user's role

**POST /api/auth/org/:slugOrId/invite**
- Requires valid session + admin/owner role
- Body: `{ email, role? }` (canonicalize the email through the shared helper — NFKC, trim, lowercase — and validate it, exactly as sign-up does)
- Delete any pending invitation for the same email + organization (one outstanding invite)
- Create invitation with a crypto-random token (32 bytes); store only its SHA-256 hash — the raw token exists only inside the emailed link
- Return 200

**POST /api/auth/org/invite/accept**
- Requires valid session
- Body: `{ token }`
- Hash the token and look up the invitation by `tokenHash`; verify not expired
- **Verify the invitee**: the signed-in user's email must equal the invitation's email (compare normalized) AND the user's `emailVerified` must be true — otherwise any signed-in account that obtains the link joins the org as the invitee (invitation takeover)
- Consume the invitation atomically (conditional delete — see `references/pitfalls/single-use-token-race.md`), then create the membership
- Return organization + membership

**GET /api/auth/org/:slugOrId/members**
- Requires valid session + membership
- Return list of members with roles

**PATCH /api/auth/org/:slugOrId/members/:userId**
- Requires valid session + admin/owner role — and that check runs **before** the requested role is validated against the role set (the ordering fix better-auth shipped in 1.7) or the target member is looked up. Validation errors are observable: a caller who is not an admin must get the same 403 whether the role exists or not, or the endpoint is an oracle for which roles and members exist
- Body: `{ role }` — the body carries the new role and nothing else; `id`, `organizationId`, `userId`, `createdAt` are path/server values, and the strict body schema rejects them if present
- Cannot change own role, cannot demote the last owner
- Return updated member

**DELETE /api/auth/org/:slugOrId/members/:userId**
- Requires valid session + admin/owner role (or self for leaving)
- Cannot remove the last owner
- Return 200

## Domain-Based Auto-Join (only if you build it)

"Everyone with an `@acme.com` email joins Acme automatically" is a convenience feature, not an authorization decision. The domain on an organization record is a string typed in by whoever administers that tenant, so an attacker who can create an organization claims `victimcorp.com`, and every VictimCorp employee who later signs in with Google is silently added to the attacker's org at the default role. The invitation rule above does not catch this — it checks the *actor*, and here the joining user is a bystander with a genuinely verified email who never clicked anything.

**Claiming a domain** (admin/owner only):

- Normalize before storing: trim, lowercase, strip a trailing dot and any scheme prefix. One row per domain — never a delimited column, never a boolean on the organization row
- Reject any claim whose value is a public suffix (`com`, `co.uk`, `github.io`) — check a Public Suffix List, not a label count
- Store with `verifiedAt = null` and a fresh crypto-random `challengeToken`. Editing the domain clears `verifiedAt` and reissues the token
- Prove control out of band: a DNS TXT record at a per-row challenge label, or a file at a well-known HTTPS path on the apex
- The proof lookup is asynchronous, so write `verifiedAt` with a conditional update guarded on the row id **and** the exact domain string read before the lookup — a concurrent edit to the row must make that write fail rather than certify a domain nobody proved. Do not add `verifiedAt IS NULL` to that guard: this write records a proof and authorizes nothing, so the flag in the guard only makes two honest re-proofs of an unchanged domain race (see `references/pitfalls/async-proof-value-binding.md`)

**Granting membership.** Auto-join runs only when every one of these holds; any failure returns with no side effects:

1. The feature is explicitly turned on. "Domain verification is not configured" means the code path is **off** — never degrade it to matching unverified claims. A check that only applies when an optional flag is set is not a control
2. The matching `OrganizationDomain` row has a non-null `verifiedAt`
3. The joining user's `emailVerified` is true, read from a freshly loaded database row — not from the user object carried through the sign-in flow
4. Both sides are normalized identically, and matching is `emailDomain === claim || emailDomain.endsWith("." + claim)`. A bare `endsWith(claim)` matches `evilacme.com` against `acme.com`
5. Exactly one organization matches. Two matching rows means refuse — never take the first
6. The user is not already a member, and no pending invitation exists for that organization and that normalized email. An invitation carries a role an admin chose deliberately; auto-joining at the default role would silently override it, so the invitation flow wins

Notify the user that they were added, on top of the audit entry — silent placement into an organization is the part a victim cannot detect.

## Implementation Rules

- Slugs: lowercase, alphanumeric + hyphens, 3-48 chars
- Role hierarchy: owner > admin > member
- Users can only modify roles below their own level
- Every route touching an organization resolves the organization id **once** and calls one shared predicate (`canManageOrg(userId, orgId)`) — including the create route, which is the one that drifts to a weaker rule than its siblings. See `references/pitfalls/authorization-must-match-the-action.md`
- There must always be at least one owner
- Membership and role grants have exactly one implementation — org creation, invitation acceptance, any automatic provisioning (SSO domain auto-join, directory sync), the admin console, and seed or backfill scripts all call it, and it owns the role-hierarchy check, the least-privilege default, and the audit record. Grep for direct inserts into OrganizationMember: each one is a side door around all three, and the `(organizationId, userId)` unique constraint — not an "is already a member" read before the insert — is what settles two concurrent grants.
- If the organization has a seat cap (plan limits, "max N members"), enforce it with a `memberCount` column on the organization row bumped by a **guarded atomic increment** in the same transaction as the member insert — `UPDATE organization SET member_count = member_count + 1 WHERE id = $1 AND member_count < $2`, proceed only if exactly one row changed, and decrement in the same transaction as a removal. Never `count` → compare → `insert`, and note that a `count(*)`-guarded conditional insert is **not** race-free either under READ COMMITTED: two concurrent accepts of the last seat both snapshot `cap − 1` and both insert, so the "limit" is one over on every burst — it only holds under SERIALIZABLE with retry, or behind `SELECT … FROM organization WHERE id = $1 FOR UPDATE`. The row-locked guarded update is what settles it (better-auth 1.7 moved its team counters to exactly this shape).
- Invitation tokens are crypto-random (32 bytes), stored hashed, single-use (consumed atomically)
- Accepting an invitation requires the accepter's verified email to match the invited address
- Invitations expire after 7 days by default
- Domain-based auto-join, if built, requires a proven domain (DNS TXT or well-known file) **and** the joining user's verified email — a claimed-but-unproven domain never grants membership
- A user can belong to multiple organizations

## Best Practices (Industry Consensus)

- **Three-role minimum: owner > admin > member.** GitHub, Clerk.dev, and WorkOS all use at least this hierarchy. Owners have destructive powers (delete org, billing), admins manage people, members have read access. Custom roles can extend this but the base three are essential.
- **Always maintain at least one owner to prevent org lockout.** Block demotion or removal of the last owner at the API level. GitHub enforces this strictly — an org cannot exist without an owner.
- **Slug format: lowercase alphanumeric + hyphens, 3-48 chars.** Must match `^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$`. No leading/trailing hyphens, no consecutive hyphens. Used in URLs and API paths, so must be URL-safe.
- **Invitation tokens: 32 bytes crypto-random, 7-day expiry, single-use.** Delete or mark as consumed after acceptance. Re-inviting the same email should invalidate the prior token. Acceptance must verify the accepting account's **verified** email matches the invited address — a forwarded or leaked invite link must not let an arbitrary account join as the invitee.
- **Audit logging for membership changes.** Record who invited, accepted, changed roles, or removed members with timestamps. GitHub provides a detailed audit log for all org-level actions. This is critical for compliance (SOC 2, ISO 27001).
- **Least-privilege by default.** New members should get the lowest role ("member") unless explicitly elevated. Invitation role should be capped at the inviter's own role level.
- **An email-domain match is a heuristic; only an explicit binding is authorization.** An invitation or a role grant is a decision an authorized actor made. A string match on the domain half of an email address is a guess about who someone works for, and it can carry a privilege grant only when DNS-level or cryptographic proof of that domain sits behind it. Google Workspace, Microsoft Entra ID, and Okta all require a published DNS record before a domain confers any tenant membership.
