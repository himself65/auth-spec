import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import type { AuthResponse, SessionListItem } from './types.js';
import { randomEmail, randomPassword, assertStatus, assertHasField, assertNoField } from './test-cases.js';

const TEST_PASSWORD = randomPassword();

export const multiSessionTestCases: AuthTestCase[] = [
  // --- multi-session ---
  {
    name: 'lists all active sessions',
    category: 'multi-session' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'multi-session sign-up');
      const token1 = (signUp.body as AuthResponse).token;

      // Sign in again to create a second session
      const signIn = await client.signIn({ email, password: TEST_PASSWORD });
      assertStatus(signIn.status, 200, 'multi-session sign-in');
      const token2 = (signIn.body as AuthResponse).token;

      const res = await client.listSessions(token2);
      assertStatus(res.status, 200, 'list sessions');
      const body = res.body as { sessions: SessionListItem[] };
      assertHasField(body as unknown as Record<string, unknown>, 'sessions', 'list sessions response');

      if (!Array.isArray(body.sessions) || body.sessions.length < 2) {
        throw new Error(
          `list sessions: expected at least 2 sessions, got ${Array.isArray(body.sessions) ? body.sessions.length : 'non-array'}`,
        );
      }
    },
  },
  {
    name: 'session list includes current session marker',
    category: 'multi-session' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'multi-session sign-up');
      const token = (signUp.body as AuthResponse).token;

      const res = await client.listSessions(token);
      assertStatus(res.status, 200, 'list sessions');
      const body = res.body as { sessions: SessionListItem[] };

      const currentSessions = body.sessions.filter((s) => s.current === true);
      if (currentSessions.length === 0) {
        throw new Error(
          'session list: expected at least one session with current: true',
        );
      }
    },
  },
  {
    name: 'session list does not expose tokens',
    category: 'multi-session' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'multi-session sign-up');
      const token = (signUp.body as AuthResponse).token;

      const res = await client.listSessions(token);
      assertStatus(res.status, 200, 'list sessions');
      const body = res.body as { sessions: SessionListItem[] };

      for (const session of body.sessions) {
        assertNoField(session as unknown as Record<string, unknown>, 'token', 'session list item');
      }
    },
  },
  {
    name: 'revoke specific session',
    category: 'multi-session' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'multi-session sign-up');

      // Sign in again to create a second session
      const signIn = await client.signIn({ email, password: TEST_PASSWORD });
      assertStatus(signIn.status, 200, 'multi-session sign-in');
      const token = (signIn.body as AuthResponse).token;

      // List sessions and find the non-current one
      const listBefore = await client.listSessions(token);
      assertStatus(listBefore.status, 200, 'list sessions before revoke');
      const beforeBody = listBefore.body as { sessions: SessionListItem[] };
      const countBefore = beforeBody.sessions.length;

      const nonCurrent = beforeBody.sessions.find((s) => s.current !== true);
      if (!nonCurrent) {
        throw new Error('revoke session: could not find a non-current session to revoke');
      }

      // Revoke the non-current session
      const revokeRes = await client.revokeSession(token, nonCurrent.id);
      assertStatus(revokeRes.status, 200, 'revoke session');

      // List sessions again — should have 1 fewer
      const listAfter = await client.listSessions(token);
      assertStatus(listAfter.status, 200, 'list sessions after revoke');
      const afterBody = listAfter.body as { sessions: SessionListItem[] };

      if (afterBody.sessions.length !== countBefore - 1) {
        throw new Error(
          `revoke session: expected ${countBefore - 1} sessions after revoke, got ${afterBody.sessions.length}`,
        );
      }
    },
  },
  {
    name: 'revoke all sessions except current',
    category: 'multi-session' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'multi-session sign-up');

      // Sign in 3 more times to create 4 total sessions
      const signIn1 = await client.signIn({ email, password: TEST_PASSWORD });
      assertStatus(signIn1.status, 200, 'multi-session sign-in 1');
      const signIn2 = await client.signIn({ email, password: TEST_PASSWORD });
      assertStatus(signIn2.status, 200, 'multi-session sign-in 2');
      const signIn3 = await client.signIn({ email, password: TEST_PASSWORD });
      assertStatus(signIn3.status, 200, 'multi-session sign-in 3');
      const token = (signIn3.body as AuthResponse).token;

      // Revoke all sessions
      const revokeRes = await client.revokeAllSessions(token);
      assertStatus(revokeRes.status, 200, 'revoke all sessions');
      const revokeBody = revokeRes.body as { revoked: number };
      assertHasField(revokeBody as unknown as Record<string, unknown>, 'revoked', 'revoke all response');

      if (revokeBody.revoked < 3) {
        throw new Error(
          `revoke all: expected revoked >= 3, got ${revokeBody.revoked}`,
        );
      }

      // List sessions — should have exactly 1 (the current)
      const listRes = await client.listSessions(token);
      assertStatus(listRes.status, 200, 'list sessions after revoke all');
      const listBody = listRes.body as { sessions: SessionListItem[] };

      if (listBody.sessions.length !== 1) {
        throw new Error(
          `revoke all: expected exactly 1 session remaining, got ${listBody.sessions.length}`,
        );
      }

      if (listBody.sessions[0].current !== true) {
        throw new Error('revoke all: the remaining session should be the current one');
      }
    },
  },
  {
    name: 'list requires authentication',
    category: 'multi-session' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.listSessions('invalid-token-that-does-not-exist');
      assertStatus(res.status, 401, 'list sessions without valid token');
    },
  },
];
