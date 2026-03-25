import type { TestConfig, AuthResponse, SessionResponse } from './types.js';

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

  async signUp(body: {
    email: string;
    password: string;
    name?: string;
  }): Promise<{ status: number; body: AuthResponse | Record<string, unknown> }> {
    const res = await this.request('/sign-up', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { status: res.status, body: await res.json() };
  }

  async signIn(body: {
    email: string;
    password: string;
  }): Promise<{ status: number; body: AuthResponse | Record<string, unknown> }> {
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
}
