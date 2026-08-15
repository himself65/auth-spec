# Pitfall: A passwordless proof must strip credentials that predate it

Sign-up is enumeration-safe by design — it returns the same 200 whether or not the address was taken — so anyone can plant a row on `victim@corp.com` with a password of their own choosing and wait. Months later the owner signs in with a magic link or an email OTP. The verify handler does "create or find User", finds the planted row, and mints the owner a session on an account the planter's password still opens. Both people now hold it. This is pre-account hijacking (CWE-287); better-auth shipped it as GHSA-qq9h-g4jm-xgf3.

Gating password sign-in on `emailVerified` does not close it — the passwordless proof is precisely the event that flips that flag, so the gate lifts the moment the owner arrives.

A fresh proof of control over an identifier outranks everything the row held before that proof. When a magic-link, email-OTP, or SMS-OTP verify resolves to an existing row whose identifier was never verified, claim that row with a conditional update — flip the identifier to verified only where it is still unverified — then delete every credential the row carries — Account, Passkey, TwoFactor, ApiKey — and every Session for that user, and only then mint the new session. All of it in one transaction, so the order inside is unobservable from outside: no caller ever sees a verified row that still carries credentials predating the proof.

The verified flag belongs in *this* guard because winning the flip is what authorizes the strip: it serializes concurrent proofs to exactly one stripper, and it encodes a correctness condition — a row that is **already** verified must never be stripped, because its credentials belong to the owner who proved it. The flag is *added* to the value binding, not substituted for it: the guard must also name the identifier the token was issued for, or an address change racing the round trip inherits a proof that was never made about it (`references/pitfalls/async-proof-value-binding.md`). A conditional write that only records a proof and authorizes nothing keeps the flag out of its guard and binds the value alone.

```typescript
// BAD — adopts whatever was already there; the planter's password survives
const user = (await db.user.findUnique({ where: { email } }))
  ?? (await db.user.create({ data: { email, emailVerified: true } }));
return createSession(user.id);

// GOOD — the verified flip *is* the gate; winning it earns the right to strip
const user = (await db.user.findUnique({ where: { email } }))
  ?? (await db.user.create({ data: { email, emailVerified: true } }));
await db.$transaction(async (tx) => {
  const claimed = await tx.user.updateMany({
    where: { id: user.id, email, emailVerified: false },  // bind the address proved
    data: { emailVerified: true },
  });
  if (claimed.count !== 1) {                        // no row flipped: which of the three?
    const row = await tx.user.findUnique({ where: { id: user.id } });
    if (!row || row.email !== email) throw new HttpError(401, 'Invalid'); // gone, or re-addressed
    return;                                         // already verified — nothing predates this proof
  }
  for (const t of [tx.account, tx.passkey, tx.twoFactor, tx.apiKey, tx.session]) {
    await t.deleteMany({ where: { userId: user.id } });   // every credential, not just the password
  }
});
return createSession(user.id);
```

In raw SQL the gate is one statement: `UPDATE users SET email_verified = true WHERE id = $1 AND email = $2 AND email_verified = false RETURNING id` — strip only if a row came back. Nothing came back means one of three things, and they are not the same outcome: the row is still there, still holds the proven address and is already verified, so skip the strip and sign in; the row is gone (deleted mid-flight); or it now holds a different address, so the proof says nothing about it. The last two abort with the generic 401 and mint nothing.

Delete the credential row rather than blanking its `passwordHash`; a nullable hash left behind is a resurrection path for any code that reads "no password" as "set one freely". Strip *every* credential the row carries, not just the password — a passkey or linked OAuth account registered on a never-verified row is equally unproven, and under `references/pitfalls/oauth-account-linking.md` a row that is still unverified cannot be carrying a link whose IdP asserted a verified email, so nothing proven is lost. The flow is never refused: the owner signs in normally and recovers a password through password reset. The dedicated confirm-your-email link is exempt — it was issued in response to the very sign-up that set the password, so it confirms that password instead of adopting a stranger's. And the identifier being proven sets the scope: if the row already carries a *different*, already-verified identifier (an established account that merely claims an unverified phone number), do not strip and do not sign in — return the generic 401 and let the owner attach the new identifier from an authenticated session.
