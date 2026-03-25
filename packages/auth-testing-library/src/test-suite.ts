import { AuthClient } from './client.js';
import { authTestCases } from './test-cases.js';
import type { AuthTestCase } from './test-cases.js';
import type { TestConfig, TestResult, TestSuiteResult } from './types.js';

import { emailOtpTestCases } from './test-cases-email-otp.js';
import { magicLinkTestCases } from './test-cases-magic-link.js';
import { phoneTestCases } from './test-cases-phone.js';
import { twoFactorTestCases } from './test-cases-two-factor.js';
import { multiSessionTestCases } from './test-cases-multi-session.js';
import { usernameTestCases } from './test-cases-username.js';
import { organizationTestCases } from './test-cases-organization.js';
import { apiKeyTestCases } from './test-cases-api-key.js';

/** All feature test case modules, keyed by feature name. */
export const featureTestCases: Record<string, AuthTestCase[]> = {
  'email-otp': emailOtpTestCases,
  'magic-link': magicLinkTestCases,
  phone: phoneTestCases,
  'two-factor': twoFactorTestCases,
  'multi-session': multiSessionTestCases,
  username: usernameTestCases,
  organization: organizationTestCases,
  'api-key': apiKeyTestCases,
};

async function runCases(
  client: AuthClient,
  cases: AuthTestCase[],
): Promise<TestResult[]> {
  const results: TestResult[] = [];
  for (const test of cases) {
    const start = performance.now();
    try {
      await test.fn(client);
      results.push({
        name: `${test.category}: ${test.name}`,
        passed: true,
        durationMs: Math.round(performance.now() - start),
      });
    } catch (err) {
      results.push({
        name: `${test.category}: ${test.name}`,
        passed: false,
        error: err instanceof Error ? err.message : String(err),
        durationMs: Math.round(performance.now() - start),
      });
    }
  }
  return results;
}

/**
 * Run the core auth test suite.
 * Optionally include feature-specific tests by passing feature names.
 */
export async function runTestSuite(
  config: TestConfig,
  features?: string[],
): Promise<TestSuiteResult> {
  const client = new AuthClient(config);
  const suiteStart = performance.now();

  // Always run core tests
  const results = await runCases(client, authTestCases);

  // Run requested feature tests
  if (features) {
    for (const feature of features) {
      const cases = featureTestCases[feature];
      if (cases) {
        const featureResults = await runCases(client, cases);
        results.push(...featureResults);
      }
    }
  }

  const passed = results.filter((r) => r.passed).length;
  const failed = results.filter((r) => !r.passed).length;

  return {
    passed,
    failed,
    skipped: 0,
    total: results.length,
    durationMs: Math.round(performance.now() - suiteStart),
    results,
  };
}
