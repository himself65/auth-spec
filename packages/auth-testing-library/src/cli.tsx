#!/usr/bin/env node

import React, { useState, useEffect } from 'react';
import { render, Box, Text, useApp } from 'ink';
import { Spinner, StatusMessage } from '@inkjs/ui';
import { runTestSuite } from './test-suite.js';
import type { TestConfig, TestResult } from './types.js';

let exitCode = 0;

// --- arg parsing (no JSX needed) ---

function printUsage(): void {
  console.log(`
auth-testing-library — conformance tests for auth-spec endpoints

Usage:
  npx auth-testing-library <base-url> [options]

Arguments:
  base-url          The server base URL (e.g. http://localhost:3000)

Options:
  --base-path PATH  Auth endpoint base path (default: /api/auth)
  --timeout MS      Request timeout in ms (default: 5000)
  --json            Output results as JSON
  -h, --help        Show this help

Examples:
  npx auth-testing-library http://localhost:3000
  npx auth-testing-library http://localhost:8080 --base-path /auth
  npx auth-testing-library http://localhost:3000 --json
`);
}

interface ParsedArgs {
  config: TestConfig;
  json: boolean;
}

function parseArgs(args: string[]): ParsedArgs | null {
  const positional: string[] = [];
  let basePath = '/api/auth';
  let timeout = 5000;
  let json = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') {
      printUsage();
      process.exit(0);
    } else if (arg === '--base-path') {
      basePath = args[++i] ?? '/api/auth';
    } else if (arg === '--timeout') {
      timeout = parseInt(args[++i] ?? '5000', 10);
    } else if (arg === '--json') {
      json = true;
    } else if (!arg.startsWith('-')) {
      positional.push(arg);
    } else {
      console.error(`Unknown option: ${arg}`);
      return null;
    }
  }

  if (positional.length === 0) {
    return null;
  }

  return {
    config: { baseUrl: positional[0], basePath, timeout },
    json,
  };
}

// --- ink components ---

function TestResultRow({ result }: { result: TestResult }) {
  return (
    <Box flexDirection="column">
      <Box gap={1}>
        <Text color={result.passed ? 'green' : 'red'}>
          {result.passed ? '✓' : '✗'}
        </Text>
        <Text>{result.name}</Text>
        <Text dimColor>({result.durationMs}ms)</Text>
      </Box>
      {!result.passed && result.error && (
        <Box marginLeft={4}>
          <Text color="red">{result.error}</Text>
        </Box>
      )}
    </Box>
  );
}

function Summary({
  passed,
  failed,
  total,
  durationMs,
}: {
  passed: number;
  failed: number;
  total: number;
  durationMs: number;
}) {
  return (
    <Box marginTop={1} gap={1}>
      <Text color="green" bold>{passed} passed</Text>
      {failed > 0 && <Text color="red" bold>{failed} failed</Text>}
      <Text dimColor>{total} total in {durationMs}ms</Text>
    </Box>
  );
}

type AppState =
  | { phase: 'connecting' }
  | { phase: 'running'; completed: TestResult[] }
  | { phase: 'done'; results: TestResult[]; passed: number; failed: number; total: number; durationMs: number }
  | { phase: 'error'; message: string };

function App({ config }: { config: TestConfig }) {
  const { exit } = useApp();
  const [state, setState] = useState<AppState>({ phase: 'connecting' });

  // Exit after terminal states render
  useEffect(() => {
    if (state.phase === 'done') {
      exitCode = state.failed > 0 ? 1 : 0;
      exit();
    } else if (state.phase === 'error') {
      exitCode = 1;
      exit();
    }
  }, [state.phase]);

  useEffect(() => {
    let cancelled = false;

    async function run() {
      // Preflight check
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), config.timeout);
        await fetch(config.baseUrl, { method: 'HEAD', signal: controller.signal }).catch(() =>
          fetch(config.baseUrl, { method: 'GET', signal: controller.signal }),
        );
        clearTimeout(timer);
      } catch {
        if (!cancelled) {
          setState({ phase: 'error', message: `Could not connect to ${config.baseUrl}. Make sure your server is running.` });
        }
        return;
      }

      if (!cancelled) {
        setState({ phase: 'running', completed: [] });
      }

      const result = await runTestSuite(config);

      if (!cancelled) {
        setState({
          phase: 'done',
          results: result.results,
          passed: result.passed,
          failed: result.failed,
          total: result.total,
          durationMs: result.durationMs,
        });
      }
    }

    run();
    return () => { cancelled = true; };
  }, [config]);

  return (
    <Box flexDirection="column" paddingTop={1}>
      <Text bold>auth-testing-library v0.0.1</Text>
      <Text dimColor>Testing: {config.baseUrl}{config.basePath}</Text>
      <Box marginTop={1} flexDirection="column">
        {state.phase === 'connecting' && (
          <Spinner label="Connecting to server..." />
        )}

        {state.phase === 'running' && (
          <>
            {state.completed.map((r, i) => (
              <TestResultRow key={i} result={r} />
            ))}
            <Spinner label="Running tests..." />
          </>
        )}

        {state.phase === 'done' && (
          <>
            {state.results.map((r, i) => (
              <TestResultRow key={i} result={r} />
            ))}
            <Summary
              passed={state.passed}
              failed={state.failed}
              total={state.total}
              durationMs={state.durationMs}
            />
          </>
        )}

        {state.phase === 'error' && (
          <StatusMessage variant="error">{state.message}</StatusMessage>
        )}
      </Box>
    </Box>
  );
}

// --- main ---

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  if (!parsed) {
    printUsage();
    process.exit(1);
    return;
  }

  const { config, json } = parsed;

  if (json) {
    // JSON mode: skip ink, just run and print
    try {
      const result = await runTestSuite(config);
      console.log(JSON.stringify(result, null, 2));
      process.exit(result.failed > 0 ? 1 : 0);
    } catch (err) {
      console.error(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      process.exit(1);
    }
    return;
  }

  const instance = render(<App config={config} />);
  await instance.waitUntilExit();
  process.exit(exitCode);
}

main();
