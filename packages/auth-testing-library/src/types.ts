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

// --- Feature: Email OTP ---

export interface EmailOtpSendResponse {
  success?: boolean;
  message?: string;
}

export interface EmailOtpVerifyResponse {
  user: {
    id: string;
    email: string;
    name?: string | null;
  };
  token: string;
}

// --- Feature: Magic Link ---

export interface MagicLinkSendResponse {
  success?: boolean;
  message?: string;
}

// --- Feature: Phone Number ---

export interface PhoneSendResponse {
  success?: boolean;
  message?: string;
}

export interface PhoneVerifyResponse {
  user: {
    id: string;
    email?: string | null;
    phoneNumber?: string;
    phone_number?: string;
  };
  token: string;
}

// --- Feature: Two-Factor ---

export interface TwoFactorEnableResponse {
  secret: string;
  uri: string;
  backupCodes: string[];
  backup_codes?: string[];
  qrCode?: string;
  qr_code?: string;
}

export interface TwoFactorChallengeResponse {
  user: {
    id: string;
    email: string;
    name?: string | null;
  };
  token: string;
}

export interface TwoFactorSignInResponse {
  twoFactorRequired?: boolean;
  two_factor_required?: boolean;
  token: string;
}

// --- Feature: Multi-Session ---

export interface SessionListItem {
  id: string;
  createdAt?: string;
  created_at?: string;
  expiresAt?: string;
  expires_at?: string;
  userAgent?: string;
  user_agent?: string;
  ipAddress?: string;
  ip_address?: string;
  current: boolean;
}

export interface SessionListResponse {
  sessions: SessionListItem[];
}

export interface SessionRevokeAllResponse {
  revoked: number;
}

// --- Feature: Username ---

export interface UsernameUpdateResponse {
  user: {
    id: string;
    email: string;
    username: string;
    name?: string | null;
  };
}

// --- Feature: Organization ---

export interface OrgResponse {
  id: string;
  name: string;
  slug: string;
  role?: string;
}

export interface OrgMemberResponse {
  id: string;
  userId?: string;
  user_id?: string;
  role: string;
  user?: {
    id: string;
    email: string;
    name?: string | null;
  };
}

export interface OrgInviteResponse {
  success?: boolean;
  token?: string;
}

// --- Feature: API Keys ---

export interface ApiKeyCreateResponse {
  id: string;
  name: string;
  key: string;
  prefix: string;
  scopes?: string[];
  expiresAt?: string | null;
  expires_at?: string | null;
  createdAt?: string;
  created_at?: string;
}

export interface ApiKeyListItem {
  id: string;
  name: string;
  prefix: string;
  scopes?: string[];
  expiresAt?: string | null;
  expires_at?: string | null;
  lastUsedAt?: string | null;
  last_used_at?: string | null;
  createdAt?: string;
  created_at?: string;
}
