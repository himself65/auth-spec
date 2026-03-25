/**
 * @auth-spec/testing
 *
 * HTTP-based conformance tests for auth-spec endpoints.
 */

export type { TestConfig, TestResult, TestSuiteResult, AuthResponse, SessionResponse } from './types.js';
export type { AuthTestCase, AuthTestFn, AuthTestCategory } from './test-cases.js';
export { AuthClient } from './client.js';
export {
  authTestCases,
  randomEmail,
  randomName,
  randomPassword,
  assertStatus,
  assertHasField,
  assertNoField,
} from './test-cases.js';
export { runTestSuite } from './test-suite.js';
