import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import { randomEmail, assertStatus, assertHasField, assertNoField } from './test-cases.js';

export const magicLinkTestCases: AuthTestCase[] = [
  // --- magic-link ---
  {
    name: 'send returns 200 for any email',
    category: 'magic-link' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const res = await client.sendMagicLink({ email });
      assertStatus(res.status, 200, 'magic-link send');
    },
  },
  {
    name: 'verify rejects invalid token',
    category: 'magic-link' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.verifyMagicLink({ token: 'invalid-token-does-not-exist' });
      assertStatus(res.status, 401, 'magic-link verify invalid token');
    },
  },
  {
    name: 'verify rejects empty token',
    category: 'magic-link' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.verifyMagicLink({ token: '' });
      assertStatus(res.status, 401, 'magic-link verify empty token');
    },
  },
  {
    name: 'send does not reveal if email exists',
    category: 'magic-link' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();

      const res1 = await client.sendMagicLink({ email });
      assertStatus(res1.status, 200, 'magic-link send first');

      const res2 = await client.sendMagicLink({ email });
      assertStatus(res2.status, 200, 'magic-link send second');

      const body1 = res1.body as Record<string, unknown>;
      const body2 = res2.body as Record<string, unknown>;
      assertNoField(body1, 'userExists', 'magic-link send first response');
      assertNoField(body2, 'userExists', 'magic-link send second response');
    },
  },
  {
    name: 'verify error does not leak user info',
    category: 'magic-link' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.verifyMagicLink({ token: 'random-token-for-leak-test' });
      assertStatus(res.status, 401, 'magic-link verify leak check');

      const body = res.body as Record<string, unknown>;
      const bodyStr = JSON.stringify(body).toLowerCase();

      const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
      if (emailPattern.test(bodyStr)) {
        throw new Error(
          'user data leak: magic-link verify error response contains an email address',
        );
      }
    },
  },
];
