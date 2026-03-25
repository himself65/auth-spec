import type { AuthClient } from './client.js';
import type { AuthTestCase, AuthTestCategory } from './test-cases.js';
import type { AuthResponse, OrgResponse, OrgMemberResponse } from './types.js';
import { randomEmail, randomName, randomPassword, assertStatus, assertHasField } from './test-cases.js';
import { faker } from '@faker-js/faker';

const TEST_PASSWORD = randomPassword();

function randomSlug(): string {
  return faker.lorem.slug(2);
}

export const organizationTestCases: AuthTestCase[] = [
  // --- organization ---
  {
    name: 'create organization',
    category: 'organization' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD, name: randomName() });
      const token = (signUp.body as AuthResponse).token;

      const slug = randomSlug();
      const res = await client.createOrg(token, { name: 'Test Org', slug });

      if (res.status !== 200 && res.status !== 201) {
        throw new Error(`create organization: expected status 200 or 201, got ${res.status}`);
      }

      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'id', 'create organization');
      assertHasField(body, 'name', 'create organization');
      assertHasField(body, 'slug', 'create organization');
    },
  },
  {
    name: 'get organization by slug',
    category: 'organization' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD, name: randomName() });
      const token = (signUp.body as AuthResponse).token;

      const slug = randomSlug();
      await client.createOrg(token, { name: 'Slug Org', slug });

      const res = await client.getOrg(token, slug);
      assertStatus(res.status, 200, 'get organization by slug');

      const body = res.body as Record<string, unknown>;
      assertHasField(body, 'id', 'get organization by slug');
      assertHasField(body, 'name', 'get organization by slug');
      assertHasField(body, 'slug', 'get organization by slug');
    },
  },
  {
    name: 'creator is owner',
    category: 'organization' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD, name: randomName() });
      const token = (signUp.body as AuthResponse).token;

      const slug = randomSlug();
      await client.createOrg(token, { name: 'Owner Org', slug });

      const res = await client.listOrgMembers(token, slug);
      assertStatus(res.status, 200, 'creator is owner: list members');

      const body = res.body as { members: OrgMemberResponse[] };
      if (!body.members || body.members.length < 1) {
        throw new Error('creator is owner: expected at least 1 member');
      }

      const owner = body.members.find((m) => m.role === 'owner');
      if (!owner) {
        throw new Error(
          'creator is owner: no member with role "owner" found among members: ' +
          body.members.map((m) => m.role).join(', '),
        );
      }
    },
  },
  {
    name: 'create requires authentication',
    category: 'organization' as AuthTestCategory,
    async fn(client: AuthClient) {
      const res = await client.createOrg('invalid-token-that-does-not-exist', {
        name: 'Unauth Org',
        slug: randomSlug(),
      });
      assertStatus(res.status, 401, 'create requires authentication');
    },
  },
  {
    name: 'rejects duplicate slug',
    category: 'organization' as AuthTestCategory,
    async fn(client: AuthClient) {
      const email = randomEmail();
      const signUp = await client.signUp({ email, password: TEST_PASSWORD, name: randomName() });
      const token = (signUp.body as AuthResponse).token;

      const slug = 'my-test-org-dup';
      await client.createOrg(token, { name: 'First Org', slug });

      const res = await client.createOrg(token, { name: 'Second Org', slug });
      assertStatus(res.status, 409, 'rejects duplicate slug');
    },
  },
  {
    name: 'non-member cannot access org',
    category: 'organization' as AuthTestCategory,
    async fn(client: AuthClient) {
      // User A creates an org
      const emailA = randomEmail();
      const signUpA = await client.signUp({ email: emailA, password: TEST_PASSWORD, name: randomName() });
      const tokenA = (signUpA.body as AuthResponse).token;

      const slug = randomSlug();
      await client.createOrg(tokenA, { name: 'Private Org', slug });

      // User B signs up separately
      const emailB = randomEmail();
      const signUpB = await client.signUp({ email: emailB, password: TEST_PASSWORD, name: randomName() });
      const tokenB = (signUpB.body as AuthResponse).token;

      // User B tries to access User A's org
      const res = await client.getOrg(tokenB, slug);
      if (res.status !== 403 && res.status !== 404) {
        throw new Error(
          `non-member cannot access org: expected status 403 or 404, got ${res.status}`,
        );
      }
    },
  },
];
