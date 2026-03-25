---
name: add-test-case
description: Add a new conformance test case to auth-testing-library. Use when adding a new test for auth endpoints (sign-up, sign-in, session, sign-out).
---

# Add Test Case

Add a new test case to `packages/auth-testing-library/src/test-cases.ts` — the `authTestCases` array.

## Step 1: Understand what to test

Ask the user what behavior they want to test. If $ARGUMENTS is provided, use that as the description.

## Step 2: Write the test case

Add a new entry to the `authTestCases` array in `test-cases.ts`. Follow these rules:

### Test structure

Every test is an `AuthTestCase` object with `name`, `category`, and `fn`:

```ts
{
  name: 'short description of what is tested',
  category: 'sign-up',
  async fn(client) {
    // test body — throws on failure
  },
},
```

### Category

Use one of the `AuthTestCategory` values:
- `sign-up` — tests for POST /api/auth/sign-up
- `sign-in` — tests for POST /api/auth/sign-in
- `session` — tests for GET /api/auth/session
- `sign-out` — tests for POST /api/auth/sign-out
- `lifecycle` — tests spanning multiple endpoints
- `security` — security-focused tests (timing, headers, etc.)

### Available helpers

These are already exported from the same file — use them, do not redefine:

```ts
// Generate test data (uses @faker-js/faker)
randomEmail()    // unique email like "Test_User12@auth-spec-test.local"
randomName()     // full name like "John Smith"
randomPassword() // strong password like "xK9#mP2$vL5@nQ8!"

// Constants (module-level in test-cases.ts)
TEST_PASSWORD    // a stable strong password for the current run
WEAK_PASSWORD    // "short" — for testing password validation

// Assertions (throw on failure)
assertStatus(actual: number, expected: number, context: string)
assertHasField(obj: Record<string, unknown>, field: string, context: string)
assertNoField(obj: Record<string, unknown>, field: string, context: string)
```

### Available client methods

The `client` parameter is an `AuthClient` with these methods:

```ts
client.signUp({ email, password, name? })  // -> { status, body }
client.signIn({ email, password })          // -> { status, body }
client.getSession(token)                    // -> { status, body }
client.signOut(token)                       // -> { status, body }
```

Each returns `{ status: number, body: object }`. Cast `body` to `AuthResponse` when you need `.token` or `.user`.

### Placement

Place the test in the correct section based on its category. The sections are marked with comments:
- `// --- sign-up ---`
- `// --- sign-in ---`
- `// --- session ---`
- `// --- sign-out ---`
- `// --- lifecycle ---`
- `// --- security ---`

### Example

```ts
{
  name: 'rejects empty email',
  category: 'sign-up',
  async fn(client) {
    const res = await client.signUp({ email: '', password: TEST_PASSWORD });
    assertStatus(res.status, 400, 'empty email sign-up');
  },
},
```

## Step 3: Verify

After adding the test, run `pnpm run build` from the repo root to verify the code compiles.
