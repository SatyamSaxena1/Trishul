import { UserManager, type User, type UserManagerSettings } from "oidc-client-ts";

export type DevPersona = {
  username: string;
  label: string;
  role: string;
  tenant_id: string;
  tenant_name: string;
};

export type PublicConfig = {
  dev_auth_enabled: boolean;
  dev_personas: DevPersona[];
  authority: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
};

export type AuthUser = {
  access_token: string;
  profile: { sub: string; name?: string };
  dev_username?: string;
};

let manager: UserManager | undefined;
let config: PublicConfig | undefined;

export async function authConfig(): Promise<PublicConfig> {
  if (config) return config;
  const response = await fetch("/api/v1/auth/config");
  if (!response.ok) throw new Error("Identity configuration is unavailable.");
  config = (await response.json()) as PublicConfig;
  return config;
}

export async function authManager(): Promise<UserManager> {
  if (manager) return manager;
  const publicConfig = await authConfig();
  if (!publicConfig.authority || !publicConfig.client_id) throw new Error("OIDC is not configured.");
  const settings: UserManagerSettings = {
    authority: publicConfig.authority,
    client_id: publicConfig.client_id,
    redirect_uri: publicConfig.redirect_uri,
    post_logout_redirect_uri: window.location.origin,
    response_type: "code",
    scope: publicConfig.scope,
    metadataUrl: `${window.location.origin}/api/v1/auth/metadata`,
    automaticSilentRenew: false,
    monitorSession: true,
  };
  manager = new UserManager(settings);
  return manager;
}

export function devSignIn(persona: DevPersona): AuthUser {
  localStorage.setItem("trishul.dev_persona", persona.username);
  localStorage.setItem("trishul.tenant", persona.tenant_id);
  return { access_token: "", dev_username: persona.username, profile: { sub: persona.username, name: persona.label } };
}

export async function signOut(user: AuthUser): Promise<void> {
  if (user.dev_username) {
    localStorage.removeItem("trishul.dev_persona");
    window.location.reload();
    return;
  }
  await (await authManager()).signoutRedirect();
}

export async function currentUser(): Promise<AuthUser | null> {
  const publicConfig = await authConfig();
  if (publicConfig.dev_auth_enabled) {
    const username = localStorage.getItem("trishul.dev_persona");
    const persona = publicConfig.dev_personas.find((item) => item.username === username);
    return persona ? devSignIn(persona) : null;
  }
  const oidc = await authManager();
  if (window.location.pathname === "/auth/callback") {
    const user = await oidc.signinRedirectCallback();
    window.history.replaceState({}, "", "/");
    return user;
  }
  const user = await oidc.getUser();
  return user && !user.expired ? user : null;
}
