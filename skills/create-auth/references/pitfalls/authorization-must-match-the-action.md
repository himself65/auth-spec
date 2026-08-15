# Pitfall: Authorize the exact value you act on, on every route that touches the resource

Two authorization bypasses come from the permission check and the operation disagreeing about what is being protected. Both survive code review because the check is right there and it does run.

**The check and the action read different sources.** Middleware authorizes the organization id from the query string; the handler reads it from the body and falls back to the caller's active organization when the body has none. A member sends an org they *may* manage in the query string and nothing in the body: the check approves that org, the handler acts on a different one. The gate passed, on a value the operation never used. Any request value that identifies a resource — id in path vs body vs query, tenant from a header vs the session — must be resolved **once**, before the check, and that single resolved value is what both the check and the operation use.

**Create is gated more weakly than read, update, and delete.** List, get, update, and delete on a resource require an admin role; the create route only checks that the caller is a member. A regular member cannot view or delete the record, but can bring one into existence — and a record that grants access is worth more to an attacker than one they can read. Every operation on a resource enforces the same boundary, and the create path is the one that drifts, because it is written first and its permission model gets tightened later on the routes that came after.

```typescript
// BAD — the gate reads one id, the handler resolves another
const authorized = await canManageOrg(session.user.id, req.query.orgId);
if (!authorized) return forbidden();
const orgId = req.body.orgId ?? session.activeOrganizationId; // ← different value
await cancelSubscription(orgId);

// GOOD — resolve once, then check and act on that one value
const orgId = req.body.orgId ?? req.query.orgId ?? session.activeOrganizationId;
if (!orgId) return badRequest();
if (!(await canManageOrg(session.user.id, orgId))) return forbidden();
await cancelSubscription(orgId);
```

Give the resource one authorization predicate — `canManageOrg(userId, orgId)` — and call it from every route that touches the resource, including create. A per-route inline role check is how the create path ends up with a weaker rule than its siblings, and how a later reader cannot tell which rule is the intended one. The same applies to a resolved *actor*: the session's user id is the value to authorize, never a `userId` taken from the request body (see `references/pitfalls/oauth-account-linking.md` for the identity-key version of the same mistake).
