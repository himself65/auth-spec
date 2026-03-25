import type {
  TestConfig,
  AuthResponse,
  SessionResponse,
  EmailOtpSendResponse,
  EmailOtpVerifyResponse,
  MagicLinkSendResponse,
  PhoneSendResponse,
  PhoneVerifyResponse,
  TwoFactorEnableResponse,
  TwoFactorChallengeResponse,
  TwoFactorSignInResponse,
  SessionListItem,
  SessionRevokeAllResponse,
  UsernameUpdateResponse,
  OrgResponse,
  OrgMemberResponse,
  OrgInviteResponse,
  ApiKeyCreateResponse,
  ApiKeyListItem,
} from './types.js';

export class AuthClient {
  private baseUrl: string;
  private timeout: number;

  constructor(config: TestConfig) {
    const base = config.baseUrl.replace(/\/$/, '');
    const path = config.basePath.replace(/\/$/, '');
    this.baseUrl = `${base}${path}`;
    this.timeout = config.timeout;
  }

  private async request(
    path: string,
    options: RequestInit = {},
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    try {
      return await fetch(`${this.baseUrl}${path}`, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });
    } finally {
      clearTimeout(timer);
    }
  }

  // --- Core Auth ---

  async signUp(body: {
    email: string;
    password: string;
    name?: string;
    username?: string;
  }): Promise<{ status: number; body: AuthResponse | Record<string, unknown> }> {
    const res = await this.request('/sign-up', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async signIn(body: {
    email?: string;
    username?: string;
    password: string;
  }): Promise<{ status: number; body: AuthResponse | TwoFactorSignInResponse | Record<string, unknown> }> {
    const res = await this.request('/sign-in', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async getSession(
    token: string,
  ): Promise<{ status: number; body: SessionResponse | Record<string, unknown> }> {
    const res = await this.request('/session', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  async signOut(
    token: string,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await this.request('/sign-out', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  // --- Email OTP ---

  async sendEmailOtp(body: {
    email: string;
  }): Promise<{ status: number; body: EmailOtpSendResponse | Record<string, unknown> }> {
    const res = await this.request('/email-otp/send', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async verifyEmailOtp(body: {
    email: string;
    code: string;
  }): Promise<{ status: number; body: EmailOtpVerifyResponse | Record<string, unknown> }> {
    const res = await this.request('/email-otp/verify', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  // --- Magic Link ---

  async sendMagicLink(body: {
    email: string;
    callbackUrl?: string;
  }): Promise<{ status: number; body: MagicLinkSendResponse | Record<string, unknown> }> {
    const res = await this.request('/magic-link/send', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async verifyMagicLink(body: {
    token: string;
  }): Promise<{ status: number; body: AuthResponse | Record<string, unknown> }> {
    const res = await this.request('/magic-link/verify', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  // --- Phone Number ---

  async sendPhoneOtp(body: {
    phoneNumber: string;
  }): Promise<{ status: number; body: PhoneSendResponse | Record<string, unknown> }> {
    const res = await this.request('/phone/send', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async verifyPhoneOtp(body: {
    phoneNumber: string;
    code: string;
  }): Promise<{ status: number; body: PhoneVerifyResponse | Record<string, unknown> }> {
    const res = await this.request('/phone/verify', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  // --- Two-Factor Auth ---

  async enableTwoFactor(
    token: string,
  ): Promise<{ status: number; body: TwoFactorEnableResponse | Record<string, unknown> }> {
    const res = await this.request('/two-factor/enable', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  async verifyTwoFactor(
    token: string,
    body: { code: string },
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await this.request('/two-factor/verify', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async disableTwoFactor(
    token: string,
    body: { code: string },
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await this.request('/two-factor/disable', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async challengeTwoFactor(
    token: string,
    body: { code: string },
  ): Promise<{ status: number; body: TwoFactorChallengeResponse | Record<string, unknown> }> {
    const res = await this.request('/two-factor/challenge', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  // --- Multi-Session ---

  async listSessions(
    token: string,
  ): Promise<{ status: number; body: { sessions: SessionListItem[] } | Record<string, unknown> }> {
    const res = await this.request('/sessions', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  async revokeSession(
    token: string,
    sessionId: string,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await this.request(`/sessions/${sessionId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  async revokeAllSessions(
    token: string,
  ): Promise<{ status: number; body: SessionRevokeAllResponse | Record<string, unknown> }> {
    const res = await this.request('/sessions', {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  // --- Username ---

  async updateUsername(
    token: string,
    body: { username: string },
  ): Promise<{ status: number; body: UsernameUpdateResponse | Record<string, unknown> }> {
    const res = await this.request('/user/username', {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  // --- Organization ---

  async createOrg(
    token: string,
    body: { name: string; slug?: string },
  ): Promise<{ status: number; body: OrgResponse | Record<string, unknown> }> {
    const res = await this.request('/org', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async getOrg(
    token: string,
    slugOrId: string,
  ): Promise<{ status: number; body: OrgResponse | Record<string, unknown> }> {
    const res = await this.request(`/org/${slugOrId}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  async inviteToOrg(
    token: string,
    slugOrId: string,
    body: { email: string; role?: string },
  ): Promise<{ status: number; body: OrgInviteResponse | Record<string, unknown> }> {
    const res = await this.request(`/org/${slugOrId}/invite`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async acceptOrgInvite(
    token: string,
    body: { token: string },
  ): Promise<{ status: number; body: OrgResponse | Record<string, unknown> }> {
    const res = await this.request('/org/invite/accept', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async listOrgMembers(
    token: string,
    slugOrId: string,
  ): Promise<{ status: number; body: { members: OrgMemberResponse[] } | Record<string, unknown> }> {
    const res = await this.request(`/org/${slugOrId}/members`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  async updateOrgMemberRole(
    token: string,
    slugOrId: string,
    userId: string,
    body: { role: string },
  ): Promise<{ status: number; body: OrgMemberResponse | Record<string, unknown> }> {
    const res = await this.request(`/org/${slugOrId}/members/${userId}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async removeOrgMember(
    token: string,
    slugOrId: string,
    userId: string,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await this.request(`/org/${slugOrId}/members/${userId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  // --- API Keys ---

  async createApiKey(
    token: string,
    body: { name: string; scopes?: string[]; expiresAt?: string },
  ): Promise<{ status: number; body: ApiKeyCreateResponse | Record<string, unknown> }> {
    const res = await this.request('/api-keys', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async listApiKeys(
    token: string,
  ): Promise<{ status: number; body: { keys: ApiKeyListItem[] } | Record<string, unknown> }> {
    const res = await this.request('/api-keys', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }

  async deleteApiKey(
    token: string,
    keyId: string,
  ): Promise<{ status: number; body: Record<string, unknown> }> {
    const res = await this.request(`/api-keys/${keyId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    return { status: res.status, body: await res.json() };
  }
}
