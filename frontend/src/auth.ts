import { UserManager, type User, type UserManagerSettings } from "oidc-client-ts";

type PublicConfig = {
  authority: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
};

let manager: UserManager | undefined;

export async function authManager(): Promise<UserManager> {
  if (manager) return manager;
  const response = await fetch("/api/v1/auth/config");
  if (!response.ok) throw new Error("Identity configuration is unavailable.");
  const config = (await response.json()) as PublicConfig;
  if (!config.authority || !config.client_id) throw new Error("OIDC is not configured.");
  const settings: UserManagerSettings = {
    authority: config.authority,
    client_id: config.client_id,
    redirect_uri: config.redirect_uri,
    post_logout_redirect_uri: window.location.origin,
    response_type: "code",
    scope: config.scope,
    metadataUrl: `${window.location.origin}/api/v1/auth/metadata`,
    automaticSilentRenew: false,
    monitorSession: true,
  };
  manager = new UserManager(settings);
  return manager;
}

export async function currentUser(): Promise<User | null> {
  const oidc = await authManager();
  if (window.location.pathname === "/auth/callback") {
    const user = await oidc.signinRedirectCallback();
    window.history.replaceState({}, "", "/");
    return user;
  }
  const user = await oidc.getUser();
  return user && !user.expired ? user : null;
}
