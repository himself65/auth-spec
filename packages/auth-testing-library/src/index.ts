/**
 * @auth-spec/testing
 *
 * HTTP-based conformance tests for auth-spec endpoints.
 */

export type {
  TestConfig,
  TestResult,
  TestSuiteResult,
  AuthResponse,
  SessionResponse,
  PasskeyRegistrationOptionsResponse,
  PasskeyRegistrationVerifyResponse,
  PasskeyAuthenticationOptionsResponse,
  PasskeyListItem,
  EmailOtpSendResponse,
  EmailOtpVerifyResponse,
  MagicLinkSendResponse,
  PhoneSendResponse,
  PhoneVerifyResponse,
  TwoFactorEnableResponse,
  TwoFactorChallengeResponse,
  TwoFactorSignInResponse,
  SessionListItem,
  SessionListResponse,
  SessionRevokeAllResponse,
  UsernameUpdateResponse,
  OrgResponse,
  OrgMemberResponse,
  OrgInviteResponse,
  ApiKeyCreateResponse,
  ApiKeyListItem,
} from './types.js';
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
export { passkeyTestCases } from './test-cases-passkey.js';
export { emailOtpTestCases } from './test-cases-email-otp.js';
export { magicLinkTestCases } from './test-cases-magic-link.js';
export { phoneTestCases } from './test-cases-phone.js';
export { twoFactorTestCases } from './test-cases-two-factor.js';
export { multiSessionTestCases } from './test-cases-multi-session.js';
export { usernameTestCases } from './test-cases-username.js';
export { organizationTestCases } from './test-cases-organization.js';
export { apiKeyTestCases } from './test-cases-api-key.js';
export { runTestSuite, featureTestCases } from './test-suite.js';
