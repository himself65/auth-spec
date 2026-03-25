import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import type { AuthResponse } from './types.js';
import { randomEmail, randomPassword, assertStatus, assertHasField } from './test-cases.js';
import { faker } from '@faker-js/faker';

const TEST_PASSWORD = randomPassword();

function randomUsername(): string {
  return faker.internet.username().toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 20);
}

export const usernameTestCases: AuthTestCase[] = [
  // --- username ---
  {
    name: 'sign-up with username',
    category: 'username',
    async fn(client) {
      const email = randomEmail();
      const username = randomUsername();
      const res = await client.signUp({ email, password: TEST_PASSWORD, username });
      assertStatus(res.status, 201, 'sign-up with username');
    },
  },
  {
    name: 'sign-in with username',
    category: 'username',
    async fn(client) {
      const email = randomEmail();
      const username = randomUsername();
      await client.signUp({ email, password: TEST_PASSWORD, username });

      const res = await client.signIn({ username, password: TEST_PASSWORD });
      assertStatus(res.status, 200, 'sign-in with username');
      const body = res.body as AuthResponse;
      assertHasField(body as unknown as Record<string, unknown>, 'token', 'sign-in with username response');
      assertHasField(body as unknown as Record<string, unknown>, 'user', 'sign-in with username response');
    },
  },
  {
    name: 'rejects duplicate username',
    category: 'username',
    async fn(client) {
      const username = 'testuser_abc';
      const email1 = randomEmail();
      const email2 = randomEmail();

      await client.signUp({ email: email1, password: TEST_PASSWORD, username });
      const res = await client.signUp({ email: email2, password: TEST_PASSWORD, username });
      assertStatus(res.status, 409, 'duplicate username sign-up');
    },
  },
  {
    name: 'username is case-insensitive',
    category: 'username',
    async fn(client) {
      const email = randomEmail();
      const uppercaseUsername = 'TestUser_XYZ';

      await client.signUp({ email, password: TEST_PASSWORD, username: uppercaseUsername });

      const res = await client.signIn({ username: 'testuser_xyz', password: TEST_PASSWORD });
      assertStatus(res.status, 200, 'case-insensitive username sign-in');
    },
  },
  {
    name: 'update username',
    category: 'username',
    async fn(client) {
      const email = randomEmail();
      const username = randomUsername();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD, username });
      const token = (signUp.body as AuthResponse).token;

      const newUsername = randomUsername();
      const res = await client.updateUsername(token, { username: newUsername });
      assertStatus(res.status, 200, 'update username');
    },
  },
  {
    name: 'rejects invalid username format',
    category: 'username',
    async fn(client) {
      const email = randomEmail();
      const res = await client.signUp({ email, password: TEST_PASSWORD, username: 'ab' });
      assertStatus(res.status, 400, 'invalid username format');
    },
  },
];
