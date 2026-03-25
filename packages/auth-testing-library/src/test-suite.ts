import { AuthClient } from './client.js';
import { authTestCases } from './test-cases.js';
import type { TestConfig, TestResult, TestSuiteResult } from './types.js';

export async function runTestSuite(config: TestConfig): Promise<TestSuiteResult> {
  const client = new AuthClient(config);
  const results: TestResult[] = [];
  const suiteStart = performance.now();

  for (const test of authTestCases) {
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
