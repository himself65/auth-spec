export interface TestConfig {
  /** Base URL of the auth server (e.g. http://localhost:3000) */
  baseUrl: string;
  /** Base path for auth endpoints (default: /api/auth) */
  basePath: string;
  /** Timeout per request in ms (default: 5000) */
  timeout: number;
}

export interface TestResult {
  name: string;
  passed: boolean;
  error?: string;
  durationMs: number;
}

export interface TestSuiteResult {
  passed: number;
  failed: number;
  skipped: number;
  total: number;
  durationMs: number;
  results: TestResult[];
}

export interface AuthResponse {
  user: {
    id: string;
    email: string;
    name?: string | null;
  };
  token: string;
}

export interface SessionResponse {
  user: {
    id: string;
    email: string;
    name?: string | null;
  };
  expiresAt?: string;
  expires_at?: string;
}
