import type { User } from "oidc-client-ts";

export type Page<T> = { results: T[]; next: string | null; previous: string | null };
export type RecordBase = { id: string; version: number; created_at: string };

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export class Api {
  constructor(
    private readonly user: User,
    private readonly tenantId: string,
  ) {}

  async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers = new Headers(options.headers);
    headers.set("Authorization", `Bearer ${this.user.access_token}`);
    headers.set("Accept", "application/json");
    if (this.tenantId) headers.set("X-Trishul-Tenant", this.tenantId);
    if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
    const response = await fetch(`/api/v1/${path}`, { ...options, headers });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({}));
      throw new ApiError(response.status, problem.title ?? `Request failed (${response.status})`);
    }
    return response.status === 204 ? (undefined as T) : response.json();
  }

  list<T>(path: string) {
    return this.request<Page<T>>(path);
  }

  create<T>(path: string, body: unknown) {
    return this.request<T>(path, { method: "POST", body: JSON.stringify(body) });
  }

  update<T>(path: string, body: unknown, version: number) {
    return this.request<T>(path, { method: "PATCH", headers: { "If-Match": String(version) }, body: JSON.stringify(body) });
  }
}
