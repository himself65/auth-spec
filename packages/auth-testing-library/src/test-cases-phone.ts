import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import { assertStatus, assertNoField } from './test-cases.js';

export const phoneTestCases: AuthTestCase[] = [
  {
    name: 'send returns 200 for valid phone number',
    category: 'phone' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.sendPhoneOtp({ phoneNumber: '+15555550100' });
      assertStatus(res.status, 200, 'phone send OTP');
    },
  },
  {
    name: 'send rejects invalid phone number format',
    category: 'phone' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.sendPhoneOtp({ phoneNumber: 'not-a-phone' });
      assertStatus(res.status, 400, 'phone send invalid format');
    },
  },
  {
    name: 'verify rejects invalid code',
    category: 'phone' as AuthTestCategory,
    async fn(client: AuthClient) {
      await client.sendPhoneOtp({ phoneNumber: '+15555550101' });
      const res = await client.verifyPhoneOtp({ phoneNumber: '+15555550101', code: '000000' });
      assertStatus(res.status, 401, 'phone verify invalid code');
    },
  },
  {
    name: 'verify rejects without prior send',
    category: 'phone' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.verifyPhoneOtp({ phoneNumber: '+15555550102', code: '123456' });
      assertStatus(res.status, 401, 'phone verify without send');
    },
  },
  {
    name: 'send does not reveal if phone exists',
    category: 'phone' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res1 = await client.sendPhoneOtp({ phoneNumber: '+15555550103' });
      const res2 = await client.sendPhoneOtp({ phoneNumber: '+15555550104' });

      assertStatus(res1.status, 200, 'phone send first number');
      assertStatus(res2.status, 200, 'phone send second number');

      const body1 = res1.body as Record<string, unknown>;
      const body2 = res2.body as Record<string, unknown>;

      assertNoField(body1, 'userExists', 'phone send response 1');
      assertNoField(body1, 'user_exists', 'phone send response 1');
      assertNoField(body2, 'userExists', 'phone send response 2');
      assertNoField(body2, 'user_exists', 'phone send response 2');
    },
  },
];
