import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import { randomEmail, assertStatus, assertNoField } from './test-cases.js';

export const emailOtpTestCases: AuthTestCase[] = [
  // --- email-otp ---
  {
    name: 'send returns 200 for any email',
    category: 'email-otp' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const res = await client.sendEmailOtp({ email });
      assertStatus(res.status, 200, 'email-otp send');
    },
  },
  {
    name: 'verify rejects invalid code',
    category: 'email-otp' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      await client.sendEmailOtp({ email });
      const res = await client.verifyEmailOtp({ email, code: '000000' });
      assertStatus(res.status, 401, 'email-otp verify invalid code');
    },
  },
  {
    name: 'verify rejects expired/non-existent code',
    category: 'email-otp' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const res = await client.verifyEmailOtp({ email, code: '123456' });
      assertStatus(res.status, 401, 'email-otp verify without send');
    },
  },
  {
    name: 'send does not reveal if email exists',
    category: 'email-otp' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email1 = randomEmail();
      const email2 = randomEmail();

      const res1 = await client.sendEmailOtp({ email: email1 });
      const res2 = await client.sendEmailOtp({ email: email2 });

      assertStatus(res1.status, 200, 'email-otp send first email');
      assertStatus(res2.status, 200, 'email-otp send second email');

      const body1 = res1.body as Record<string, unknown>;
      const body2 = res2.body as Record<string, unknown>;

      assertNoField(body1, 'userExists', 'email-otp send response');
      assertNoField(body1, 'user_exists', 'email-otp send response');
      assertNoField(body2, 'userExists', 'email-otp send response');
      assertNoField(body2, 'user_exists', 'email-otp send response');

      const keys1 = Object.keys(body1).sort().join(',');
      const keys2 = Object.keys(body2).sort().join(',');
      if (keys1 !== keys2) {
        throw new Error(
          `email-otp send: response shape differs between emails ` +
          `(keys: [${keys1}] vs [${keys2}]) — this may reveal whether an email is registered`,
        );
      }
    },
  },
  {
    name: 'verify error does not leak user info',
    category: 'email-otp' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const res = await client.verifyEmailOtp({ email, code: '000000' });
      assertStatus(res.status, 401, 'email-otp verify wrong code');

      const body = res.body as Record<string, unknown>;
      const errorMsg = typeof body.error === 'string' ? body.error.toLowerCase() : '';
      const detailMsg = typeof body.detail === 'string' ? body.detail.toLowerCase() : '';
      const messageMsg = typeof body.message === 'string' ? body.message.toLowerCase() : '';
      const msg = errorMsg + ' ' + detailMsg + ' ' + messageMsg;

      if (msg.includes(email.toLowerCase())) {
        throw new Error(
          `user data leak: email-otp verify error contains the email address "${email}"`,
        );
      }

      const leakyPatterns = ['user not found', 'user does not exist', 'no user', 'no account'];
      for (const pattern of leakyPatterns) {
        if (msg.includes(pattern)) {
          throw new Error(
            `user data leak: email-otp verify error contains leaky phrase "${pattern}"`,
          );
        }
      }
    },
  },
];
