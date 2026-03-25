import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import type { AuthResponse, ApiKeyCreateResponse } from './types.js';
import { randomEmail, randomPassword, assertStatus, assertHasField, assertNoField } from './test-cases.js';

const TEST_PASSWORD = randomPassword();

export const apiKeyTestCases: AuthTestCase[] = [
  // --- api-key ---
  {
    name: 'create api key returns key and prefix',
    category: 'api-key' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const res = await client.createApiKey(token, { name: 'test-key' });
      if (res.status !== 200 && res.status !== 201) {
        throw new Error(`create api key: expected status 200 or 201, got ${res.status}`);
      }
      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'key', 'create api key');
      assertHasField(body, 'prefix', 'create api key');
      assertHasField(body, 'name', 'create api key');
      assertHasField(body, 'id', 'create api key');
    },
  },
  {
    name: 'created key is shown only once',
    category: 'api-key' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const createRes = await client.createApiKey(token, { name: 'once-key' });
      const createBody = createRes.body as ApiKeyCreateResponse;
      assertHasField(createBody as unknown as Record<string, unknown>, 'key', 'create api key');

      const listRes = await client.listApiKeys(token);
      assertStatus(listRes.status, 200, 'list api keys');
      const listBody = listRes.body as { keys: Record<string, unknown>[] };
      if (!Array.isArray(listBody.keys) || listBody.keys.length < 1) {
        throw new Error('created key is shown only once: expected at least 1 key in list');
      }
      for (const item of listBody.keys) {
        assertNoField(item, 'key', 'listed api key');
        assertHasField(item, 'prefix', 'listed api key');
      }
    },
  },
  {
    name: 'list api keys',
    category: 'api-key' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      await client.createApiKey(token, { name: 'key-one' });
      await client.createApiKey(token, { name: 'key-two' });

      const listRes = await client.listApiKeys(token);
      assertStatus(listRes.status, 200, 'list api keys');
      const listBody = listRes.body as { keys: Record<string, unknown>[] };
      if (!Array.isArray(listBody.keys) || listBody.keys.length < 2) {
        throw new Error(
          `list api keys: expected at least 2 keys, got ${Array.isArray(listBody.keys) ? listBody.keys.length : 0}`,
        );
      }
    },
  },
  {
    name: 'delete api key',
    category: 'api-key' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const createRes = await client.createApiKey(token, { name: 'delete-me' });
      const createBody = createRes.body as ApiKeyCreateResponse;
      const keyId = createBody.id;

      const deleteRes = await client.deleteApiKey(token, keyId);
      assertStatus(deleteRes.status, 200, 'delete api key');

      const listRes = await client.listApiKeys(token);
      assertStatus(listRes.status, 200, 'list after delete');
      const listBody = listRes.body as { keys: Array<{ id: string }> };
      const found = (listBody.keys ?? []).find((k) => k.id === keyId);
      if (found) {
        throw new Error(`delete api key: key ${keyId} still present in list after deletion`);
      }
    },
  },
  {
    name: 'create requires authentication',
    category: 'api-key' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.createApiKey('invalid-token-that-does-not-exist', {
        name: 'should-fail',
      });
      assertStatus(res.status, 401, 'create api key without auth');
    },
  },
  {
    name: 'api key authenticates to session endpoint',
    category: 'api-key' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const createRes = await client.createApiKey(token, { name: 'session-key' });
      const createBody = createRes.body as ApiKeyCreateResponse;
      const apiKey = createBody.key;

      const sessionRes = await client.getSession(apiKey);
      assertStatus(sessionRes.status, 200, 'session with api key');
      const sessionBody = sessionRes.body as Record<string, unknown>;
      assertHasField(sessionBody, 'user', 'session with api key');
    },
  },
];
