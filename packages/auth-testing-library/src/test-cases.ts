import { faker } from '@faker-js/faker';
import type { AuthClient } from './client.js';
import type { AuthResponse } from './types.js';

export type AuthTestFn = (client: AuthClient) => Promise<void>;

export type AuthTestCategory =
  | 'sign-up'
  | 'sign-in'
  | 'session'
  | 'sign-out'
  | 'lifecycle'
  | 'security'
  | 'email-otp'
  | 'magic-link'
  | 'phone'
  | 'two-factor'
  | 'multi-session'
  | 'username'
  | 'organization'
  | 'api-key';

export interface AuthTestCase {
  name: string;
  category: AuthTestCategory;
  fn: AuthTestFn;
}

// --- helpers ---

export function randomEmail(): string {
  return faker.internet.email({ provider: 'auth-spec-test.local' });
}

export function randomName(): string {
  return faker.person.fullName();
}

export function randomPassword(): string {
  return faker.internet.password({ length: 16, memorable: false }) + '!1Aa';
}

export function assertStatus(actual: number, expected: number, context: string): void {
  if (actual !== expected) {
    throw new Error(`${context}: expected status ${expected}, got ${actual}`);
  }
}

export function assertHasField(obj: Record<string, unknown>, field: string, context: string): void {
  if (!(field in obj) || obj[field] === undefined || obj[field] === null) {
    throw new Error(`${context}: missing field "${field}"`);
  }
}

export function assertNoField(obj: Record<string, unknown>, field: string, context: string): void {
  if (field in obj && obj[field] !== undefined && obj[field] !== null) {
    throw new Error(`${context}: should not expose "${field}"`);
  }
}

// --- test cases ---

const TEST_PASSWORD = randomPassword();
const WEAK_PASSWORD = 'short';

export const authTestCases: AuthTestCase[] = [
  // --- sign-up ---
  {
    name: 'creates user and returns token',
    category: 'sign-up',
    async fn(client) {
      const email = randomEmail();
      const res = await client.signUp({ email, password: TEST_PASSWORD, name: randomName() });
      assertStatus(res.status, 201, 'sign-up');
      const body = res.body as AuthResponse;
      assertHasField(body as unknown as Record<string, unknown>, 'token', 'sign-up response');
      assertHasField(body as unknown as Record<string, unknown>, 'user', 'sign-up response');
      assertHasField(body.user as unknown as Record<string, unknown>, 'id', 'sign-up user');
      assertHasField(body.user as unknown as Record<string, unknown>, 'email', 'sign-up user');
      if (body.user.email !== email) {
        throw new Error(`sign-up: email mismatch, expected "${email}", got "${body.user.email}"`);
      }
    },
  },
  {
    name: 'rejects duplicate email',
    category: 'sign-up',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });
      const res = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(res.status, 409, 'duplicate sign-up');
    },
  },
  {
    name: 'rejects weak password',
    category: 'sign-up',
    async fn(client) {
      const email = randomEmail();
      const res = await client.signUp({ email, password: WEAK_PASSWORD });
      assertStatus(res.status, 400, 'weak password sign-up');
    },
  },
  {
    name: 'does not expose password hash',
    category: 'sign-up',
    async fn(client) {
      const email = randomEmail();
      const res = await client.signUp({ email, password: TEST_PASSWORD });
      const body = res.body as Record<string, unknown>;
      assertNoField(body, 'passwordHash', 'sign-up response');
      assertNoField(body, 'password_hash', 'sign-up response');
      assertNoField(body, 'password', 'sign-up response');
      if (body.user && typeof body.user === 'object') {
        const user = body.user as Record<string, unknown>;
        assertNoField(user, 'passwordHash', 'sign-up user');
        assertNoField(user, 'password_hash', 'sign-up user');
        assertNoField(user, 'password', 'sign-up user');
      }
    },
  },

  // --- sign-in ---
  {
    name: 'authenticates with correct credentials',
    category: 'sign-in',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });
      const res = await client.signIn({ email, password: TEST_PASSWORD });
      assertStatus(res.status, 200, 'sign-in');
      const body = res.body as AuthResponse;
      assertHasField(body as unknown as Record<string, unknown>, 'token', 'sign-in response');
      assertHasField(body as unknown as Record<string, unknown>, 'user', 'sign-in response');
      if (body.user.email !== email) {
        throw new Error(`sign-in: email mismatch`);
      }
    },
  },
  {
    name: 'rejects wrong password',
    category: 'sign-in',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });
      const res = await client.signIn({ email, password: randomPassword() });
      assertStatus(res.status, 401, 'wrong password sign-in');
    },
  },
  {
    name: 'rejects non-existent email',
    category: 'sign-in',
    async fn(client) {
      const res = await client.signIn({ email: randomEmail(), password: TEST_PASSWORD });
      assertStatus(res.status, 401, 'non-existent email sign-in');
    },
  },
  {
    name: 'does not enumerate users (same error for wrong email vs wrong password)',
    category: 'sign-in',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });

      const wrongPw = await client.signIn({ email, password: randomPassword() });
      const wrongEmail = await client.signIn({ email: randomEmail(), password: TEST_PASSWORD });

      if (wrongPw.status !== wrongEmail.status) {
        throw new Error(
          `user enumeration: wrong-password status (${wrongPw.status}) differs from wrong-email status (${wrongEmail.status})`,
        );
      }

      const pwError = (wrongPw.body as Record<string, unknown>).error;
      const emailError = (wrongEmail.body as Record<string, unknown>).error;
      if (pwError !== emailError) {
        throw new Error(
          `user enumeration: error messages differ ("${pwError}" vs "${emailError}")`,
        );
      }
    },
  },

  // --- session ---
  {
    name: 'returns user for valid token',
    category: 'session',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;
      const res = await client.getSession(token);
      assertStatus(res.status, 200, 'get session');
      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'user', 'session response');
    },
  },
  {
    name: 'rejects invalid token',
    category: 'session',
    async fn(client) {
      const res = await client.getSession('invalid-token-that-does-not-exist');
      assertStatus(res.status, 401, 'invalid token session');
    },
  },
  {
    name: 'sign-in token works for session',
    category: 'session',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });
      const signIn = await client.signIn({ email, password: TEST_PASSWORD });
      const token = (signIn.body as AuthResponse).token;
      const res = await client.getSession(token);
      assertStatus(res.status, 200, 'sign-in token session');
    },
  },

  // --- sign-out ---
  {
    name: 'invalidates session',
    category: 'sign-out',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const outRes = await client.signOut(token);
      assertStatus(outRes.status, 200, 'sign-out');

      const sessionRes = await client.getSession(token);
      assertStatus(sessionRes.status, 401, 'session after sign-out');
    },
  },
  {
    name: 'does not affect other sessions',
    category: 'sign-out',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });

      const s1 = await client.signIn({ email, password: TEST_PASSWORD });
      const s2 = await client.signIn({ email, password: TEST_PASSWORD });
      const token1 = (s1.body as AuthResponse).token;
      const token2 = (s2.body as AuthResponse).token;

      await client.signOut(token1);

      const res = await client.getSession(token2);
      assertStatus(res.status, 200, 'other session after sign-out');
    },
  },

  // --- lifecycle ---
  {
    name: 'sign-up -> session -> sign-out -> session fails',
    category: 'lifecycle',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD, name: randomName() });
      assertStatus(signUp.status, 201, 'lifecycle sign-up');
      const token = (signUp.body as AuthResponse).token;

      const session = await client.getSession(token);
      assertStatus(session.status, 200, 'lifecycle session');

      const signOut = await client.signOut(token);
      assertStatus(signOut.status, 200, 'lifecycle sign-out');

      const expired = await client.getSession(token);
      assertStatus(expired.status, 401, 'lifecycle session after sign-out');
    },
  },
  {
    name: 'sign-up -> sign-out -> sign-in -> session works',
    category: 'lifecycle',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token1 = (signUp.body as AuthResponse).token;

      await client.signOut(token1);

      const signIn = await client.signIn({ email, password: TEST_PASSWORD });
      assertStatus(signIn.status, 200, 'lifecycle re-sign-in');
      const token2 = (signIn.body as AuthResponse).token;

      const session = await client.getSession(token2);
      assertStatus(session.status, 200, 'lifecycle session after re-sign-in');
    },
  },

  // --- security ---
  {
    name: 'sign-in timing is consistent for existing vs non-existing users',
    category: 'security',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });

      const SAMPLES = 5;
      const existingTimes: number[] = [];
      const nonExistingTimes: number[] = [];

      for (let i = 0; i < SAMPLES; i++) {
        const start = performance.now();
        await client.signIn({ email, password: randomPassword() });
        existingTimes.push(performance.now() - start);
      }

      for (let i = 0; i < SAMPLES; i++) {
        const start = performance.now();
        await client.signIn({ email: randomEmail(), password: randomPassword() });
        nonExistingTimes.push(performance.now() - start);
      }

      const avg = (arr: number[]) => arr.reduce((a, b) => a + b, 0) / arr.length;
      const avgExisting = avg(existingTimes);
      const avgNonExisting = avg(nonExistingTimes);

      const ratio = Math.max(avgExisting, avgNonExisting) / Math.min(avgExisting, avgNonExisting);
      if (ratio > 10) {
        throw new Error(
          `timing attack: avg response for existing user (${Math.round(avgExisting)}ms) vs ` +
          `non-existing user (${Math.round(avgNonExisting)}ms) differs by ${ratio.toFixed(1)}x — ` +
          `this may leak whether an email is registered`,
        );
      }
    },
  },
  {
    name: 'sign-up error does not leak that email is registered',
    category: 'security',
    async fn(client) {
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });

      const res = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(res.status, 409, 'duplicate sign-up');

      const body = res.body as Record<string, unknown>;
      const errorMsg = typeof body.error === 'string' ? body.error.toLowerCase() : '';
      const detailMsg = typeof body.detail === 'string' ? body.detail.toLowerCase() : '';
      const msg = errorMsg + ' ' + detailMsg;

      if (msg.includes(email.toLowerCase())) {
        throw new Error(
          `user data leak: sign-up error message contains the email address "${email}"`,
        );
      }

      const leakyPatterns = ['user exists', 'account exists', 'already have an account'];
      for (const pattern of leakyPatterns) {
        if (msg.includes(pattern)) {
          throw new Error(
            `user data leak: sign-up error message contains leaky phrase "${pattern}"`,
          );
        }
      }
    },
  },
];
