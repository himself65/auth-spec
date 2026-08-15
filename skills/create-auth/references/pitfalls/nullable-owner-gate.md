# Pitfall: A NULL owner column must deny, not skip the ownership check

A row representing a pending, human-approved action is created before anyone owns it — the owner column is NULL for the whole pending lifetime, which is exactly the window the check exists to protect. Written as a truthiness short-circuit, `if (rec.userId && rec.userId !== session.user.id) return forbidden()`, the guard is unreachable for every pending row: the condition is false while `userId` is NULL, the forbidden branch never runs, and any authenticated session can approve or deny any pending row. The party waiting on the approval is then bound to whoever acted first — the attacker.

This skill's own schemas plant the column: `OAuthClient.createdByUserId` is "null for self-registered" (every dynamically registered MCP client), and `PasskeyChallenge.userId` and `EmailVerificationCode.userId` are null on the sign-up and discoverable-credential paths. Any endpoint that manages those rows needs the treatment below, as does any pairing, delegated-access, or "confirm this on your other device" flow added later.

The fix has two halves: claim the row for the first authenticated session that views it, with a conditional write, and treat a still-NULL owner at act time as a hard denial rather than "not yet restricted".

```typescript
// BAD — vacuous for the entire pending lifetime; the guard is skipped, and the
// approving user is silently written in as the owner on the way past
const rec = await db.pendingApproval.findUnique({ where: { code } });
if (rec.userId && rec.userId !== session.user.id) return forbidden();
await db.pendingApproval.update({
  where: { code },
  data: { status: 'approved', userId: session.user.id },
});

// GOOD — claim on first view: one conditional write, affected rows picks the winner
await db.pendingApproval.updateMany({
  where: { code, status: 'pending', userId: null },
  data: { userId: session.user.id },
});  // 0 rows changed = another session claimed it first; the gate below denies

// …then at approve/deny time, unowned is an error, never implicit consent
const rec = await db.pendingApproval.findUnique({ where: { code } });
if (rec.userId == null) return badRequest('code not claimed');
if (rec.userId !== session.user.id) return forbidden();
await db.pendingApproval.update({ where: { code }, data: { status: 'approved' } });
```

Deny runs the identical gate and must not rewrite the owner — a rejection is not an opening for a second party to take the row. Generalize the rule past pending approvals: every nullable column that appears in an authorization predicate needs an explicit null branch, because `&&` on a nullable field does not weaken the check, it deletes it.
