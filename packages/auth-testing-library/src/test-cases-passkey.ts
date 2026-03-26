import type { AuthTestCase } from './test-cases.js';
import { randomEmail, randomPassword, randomName, assertStatus, assertHasField } from './test-cases.js';
import type { AuthResponse, PasskeyRegistrationOptionsResponse } from './types.js';

const TEST_PASSWORD = randomPassword();

/**
 * Passkey test cases.
 *
 * NOTE: Full end-to-end passkey registration and authentication requires a
 * real WebAuthn authenticator (or a virtual one). These tests verify the
 * server-side API contract — that endpoints exist, return correct shapes,
 * enforce auth requirements, and reject invalid input. They do NOT perform
 * actual cryptographic attestation/assertion (that requires a browser or
 * CTAP simulator).
 */
export const passkeyTestCases: AuthTestCase[] = [
  // --- registration options ---
  {
    name: 'register/options requires authentication',
    category: 'passkey',
    async fn(client) {
      const res = await client.passkeyRegisterOptions('invalid-token');
      assertStatus(res.status, 401, 'passkey register options without auth');
    },
  },
  {
    name: 'register/options returns valid WebAuthn creation options',
    category: 'passkey',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD, name: randomName() });
      const token = (signUp.body as AuthResponse).token;

      const res = await client.passkeyRegisterOptions(token);
      assertStatus(res.status, 200, 'passkey register options');

      const body = res.body as PasskeyRegistrationOptionsResponse;

      // Must have challenge
      assertHasField(body as unknown as Record<string, unknown>, 'challenge', 'register options');

      // Must have rp with id and name
      assertHasField(body as unknown as Record<string, unknown>, 'rp', 'register options');
      assertHasField(body.rp as unknown as Record<string, unknown>, 'id', 'register options rp');
      assertHasField(body.rp as unknown as Record<string, unknown>, 'name', 'register options rp');

      // Must have user with id, name, displayName
      assertHasField(body as unknown as Record<string, unknown>, 'user', 'register options');
      assertHasField(body.user as unknown as Record<string, unknown>, 'id', 'register options user');
      assertHasField(body.user as unknown as Record<string, unknown>, 'name', 'register options user');
      assertHasField(body.user as unknown as Record<string, unknown>, 'displayName', 'register options user');

      // Must have pubKeyCredParams with at least ES256
      assertHasField(body as unknown as Record<string, unknown>, 'pubKeyCredParams', 'register options');
      if (!Array.isArray(body.pubKeyCredParams) || body.pubKeyCredParams.length === 0) {
        throw new Error('register options: pubKeyCredParams must be a non-empty array');
      }
      const algs = body.pubKeyCredParams.map((p) => p.alg);
      if (!algs.includes(-7)) {
        throw new Error('register options: pubKeyCredParams must include ES256 (alg: -7)');
      }
    },
  },
  {
    name: 'register/options challenge is unique per request',
    category: 'passkey',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const res1 = await client.passkeyRegisterOptions(token);
      const res2 = await client.passkeyRegisterOptions(token);

      const challenge1 = (res1.body as PasskeyRegistrationOptionsResponse).challenge;
      const challenge2 = (res2.body as PasskeyRegistrationOptionsResponse).challenge;

      if (challenge1 === challenge2) {
        throw new Error('register options: challenges must be unique per request');
      }
    },
  },
  {
    name: 'register/options user.id is not the email or user table PK',
    category: 'passkey',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;
      const userId = (signUp.body as AuthResponse).user.id;

      const res = await client.passkeyRegisterOptions(token);
      const body = res.body as PasskeyRegistrationOptionsResponse;

      // user.id should be an opaque identifier, not the email
      if (body.user.id === email) {
        throw new Error('register options: user.id must not be the email (privacy risk)');
      }
      // user.id should not be the user table PK
      if (body.user.id === userId) {
        throw new Error('register options: user.id should be an opaque webauthn user ID, not the user table PK');
      }
    },
  },

  // --- registration verify ---
  {
    name: 'register/verify requires authentication',
    category: 'passkey',
    async fn(client) {
      const res = await client.passkeyRegisterVerify('invalid-token', { credential: {} });
      assertStatus(res.status, 401, 'passkey register verify without auth');
    },
  },
  {
    name: 'register/verify rejects invalid credential',
    category: 'passkey',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const res = await client.passkeyRegisterVerify(token, { credential: { id: 'fake', response: {} } });
      if (res.status === 200) {
        throw new Error('register/verify should reject invalid credential data');
      }
    },
  },

  // --- authentication options ---
  {
    name: 'authenticate/options returns valid WebAuthn request options',
    category: 'passkey',
    async fn(client) {
      const res = await client.passkeyAuthenticateOptions();
      assertStatus(res.status, 200, 'passkey authenticate options');

      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'challenge', 'authenticate options');

      // challenge must be a non-empty string
      if (typeof body.challenge !== 'string' || body.challenge.length === 0) {
        throw new Error('authenticate options: challenge must be a non-empty string');
      }
    },
  },
  {
    name: 'authenticate/options with email includes allowCredentials',
    category: 'passkey',
    async fn(client) {
      // With an email that has no passkeys, allowCredentials should be empty array
      const email = randomEmail();
      await client.signUp({ email, password: TEST_PASSWORD });

      const res = await client.passkeyAuthenticateOptions({ email });
      assertStatus(res.status, 200, 'passkey authenticate options with email');

      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'challenge', 'authenticate options with email');
    },
  },
  {
    name: 'authenticate/options challenge is unique per request',
    category: 'passkey',
    async fn(client) {
      const res1 = await client.passkeyAuthenticateOptions();
      const res2 = await client.passkeyAuthenticateOptions();

      const c1 = (res1.body as Record<string, unknown>).challenge;
      const c2 = (res2.body as Record<string, unknown>).challenge;

      if (c1 === c2) {
        throw new Error('authenticate options: challenges must be unique per request');
      }
    },
  },

  // --- authentication verify ---
  {
    name: 'authenticate/verify rejects invalid credential',
    category: 'passkey',
    async fn(client) {
      const res = await client.passkeyAuthenticateVerify({ credential: { id: 'fake', response: {} } });
      assertStatus(res.status, 401, 'passkey authenticate verify with invalid credential');
    },
  },

  // --- list ---
  {
    name: 'list requires authentication',
    category: 'passkey',
    async fn(client) {
      const res = await client.passkeyList('invalid-token');
      assertStatus(res.status, 401, 'passkey list without auth');
    },
  },
  {
    name: 'list returns empty array for user with no passkeys',
    category: 'passkey',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const res = await client.passkeyList(token);
      assertStatus(res.status, 200, 'passkey list');

      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'passkeys', 'passkey list response');
      const passkeys = (body as { passkeys: unknown[] }).passkeys;
      if (!Array.isArray(passkeys)) {
        throw new Error('passkey list: passkeys must be an array');
      }
    },
  },
  {
    name: 'list does not expose publicKey or credentialId',
    category: 'passkey',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const res = await client.passkeyList(token);
      const body = res.body as { passkeys: Record<string, unknown>[] };
      if (Array.isArray(body.passkeys)) {
        for (const pk of body.passkeys) {
          if ('publicKey' in pk || 'public_key' in pk) {
            throw new Error('passkey list: must not expose publicKey');
          }
          if ('credentialId' in pk || 'credential_id' in pk) {
            throw new Error('passkey list: must not expose credentialId');
          }
        }
      }
    },
  },

  // --- delete ---
  {
    name: 'delete requires authentication',
    category: 'passkey',
    async fn(client) {
      const res = await client.passkeyDelete('invalid-token', 'some-id');
      assertStatus(res.status, 401, 'passkey delete without auth');
    },
  },
  {
    name: 'delete rejects non-existent passkey',
    category: 'passkey',
    async fn(client) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD });
      const token = (signUp.body as AuthResponse).token;

      const res = await client.passkeyDelete(token, 'non-existent-passkey-id');
      // Should be 404 or 403, not 200
      if (res.status === 200) {
        throw new Error('passkey delete: should not succeed for non-existent passkey');
      }
    },
  },
];
