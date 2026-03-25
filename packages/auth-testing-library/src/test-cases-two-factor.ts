import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import type { TwoFactorEnableResponse } from './types.js';
import { randomEmail, randomPassword, assertStatus, assertHasField, assertNoField } from './test-cases.js';
import type { AuthResponse } from './types.js';

const TEST_PASSWORD = randomPassword();

export const twoFactorTestCases: AuthTestCase[] = [
  // --- two-factor ---
  {
    name: 'enable returns secret and backup codes',
    category: 'two-factor' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'two-factor sign-up');
      const token = (signUp.body as AuthResponse).token;

      const res = await client.enableTwoFactor(token);
      assertStatus(res.status, 200, 'two-factor enable');

      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'secret', 'two-factor enable response');
      assertHasField(body, 'uri', 'two-factor enable response');

      // Accept both camelCase and snake_case
      const backupCodes = body.backupCodes ?? body.backup_codes;
      if (backupCodes === undefined || backupCodes === null) {
        throw new Error(
          'two-factor enable response: missing field "backupCodes" (or "backup_codes")',
        );
      }
      if (!Array.isArray(backupCodes)) {
        throw new Error(
          'two-factor enable response: "backupCodes" (or "backup_codes") must be an array',
        );
      }
    },
  },
  {
    name: 'enable requires authentication',
    category: 'two-factor' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.enableTwoFactor('invalid-token');
      assertStatus(res.status, 401, 'two-factor enable without auth');
    },
  },
  {
    name: 'verify rejects invalid code',
    category: 'two-factor' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'two-factor sign-up');
      const token = (signUp.body as AuthResponse).token;

      await client.enableTwoFactor(token);

      const res = await client.verifyTwoFactor(token, { code: '000000' });
      assertStatus(res.status, 401, 'two-factor verify with invalid code');
    },
  },
  {
    name: 'disable rejects invalid code',
    category: 'two-factor' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'two-factor sign-up');
      const token = (signUp.body as AuthResponse).token;

      await client.enableTwoFactor(token);

      const res = await client.disableTwoFactor(token, { code: '000000' });
      assertStatus(res.status, 401, 'two-factor disable with invalid code');
    },
  },
  {
    name: 'challenge rejects invalid code',
    category: 'two-factor' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'two-factor sign-up');
      const token = (signUp.body as AuthResponse).token;

      await client.enableTwoFactor(token);

      const res = await client.challengeTwoFactor(token, { code: '000000' });
      assertStatus(res.status, 401, 'two-factor challenge with invalid code');
    },
  },
  {
    name: 'enable does not expose secret after setup',
    category: 'two-factor' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      assertStatus(signUp.status, 201, 'two-factor sign-up');
      const token = (signUp.body as AuthResponse).token;

      const firstEnable = await client.enableTwoFactor(token);
      assertStatus(firstEnable.status, 200, 'two-factor first enable');
      const firstBody = firstEnable.body as Record<string, unknown>;
      assertHasField(firstBody, 'secret', 'two-factor first enable response');
      const firstSecret = firstBody.secret as string;

      const secondEnable = await client.enableTwoFactor(token);
      const secondBody = secondEnable.body as Record<string, unknown>;

      // Either the second call should fail (non-200) or it should not return
      // the same secret, indicating the original secret is not re-exposed.
      if (secondEnable.status === 200) {
        const secondSecret = secondBody.secret;
        if (secondSecret === firstSecret) {
          throw new Error(
            'two-factor enable: second call returned the same secret — ' +
            'the secret should not be re-exposed after initial setup',
          );
        }
      }
      // If status is non-200 (e.g. 400 or 409), that is acceptable — the
      // server correctly rejected a duplicate enable request.
    },
  },
];
