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
| email          | string   | not null                                 |
| role           | string   | not null (default: "member")             |
| token          | string   | unique, not null                         |
| expiresAt      | datetime | not null (default: 7 days)               |
| createdAt      | datetime | default now                              |

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
- Body: `{ email, role? }`
- Create invitation with crypto-random token, send email
- Return 200

**POST /api/auth/org/invite/accept**
- Requires valid session
- Body: `{ token }`
- Verify token not expired, create membership, delete invitation
- Return organization + membership

**GET /api/auth/org/:slugOrId/members**
- Requires valid session + membership
- Return list of members with roles

**PATCH /api/auth/org/:slugOrId/members/:userId**
- Requires valid session + admin/owner role
- Body: `{ role }`
- Cannot change own role, cannot demote the last owner
- Return updated member

**DELETE /api/auth/org/:slugOrId/members/:userId**
- Requires valid session + admin/owner role (or self for leaving)
- Cannot remove the last owner
- Return 200

## Implementation Rules

- Slugs: lowercase, alphanumeric + hyphens, 3-48 chars
- Role hierarchy: owner > admin > member
- Users can only modify roles below their own level
- There must always be at least one owner
- Invitation tokens are crypto-random (32 bytes), single-use
- Invitations expire after 7 days by default
- A user can belong to multiple organizations

## Best Practices (Industry Consensus)

- **Three-role minimum: owner > admin > member.** GitHub, Clerk.dev, and WorkOS all use at least this hierarchy. Owners have destructive powers (delete org, billing), admins manage people, members have read access. Custom roles can extend this but the base three are essential.
- **Always maintain at least one owner to prevent org lockout.** Block demotion or removal of the last owner at the API level. GitHub enforces this strictly — an org cannot exist without an owner.
- **Slug format: lowercase alphanumeric + hyphens, 3-48 chars.** Must match `^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$`. No leading/trailing hyphens, no consecutive hyphens. Used in URLs and API paths, so must be URL-safe.
- **Invitation tokens: 32 bytes crypto-random, 7-day expiry, single-use.** Delete or mark as consumed after acceptance. Re-inviting the same email should invalidate the prior token.
- **Audit logging for membership changes.** Record who invited, accepted, changed roles, or removed members with timestamps. GitHub provides a detailed audit log for all org-level actions. This is critical for compliance (SOC 2, ISO 27001).
- **Least-privilege by default.** New members should get the lowest role ("member") unless explicitly elevated. Invitation role should be capped at the inviter's own role level.
