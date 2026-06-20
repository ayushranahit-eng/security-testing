const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");
export const AUTH_STORAGE_KEY = "hit-securescan-auth-v1";

export function apiUrl(path) {
  if (!API_BASE_URL) return path;

  const backendPath = path.replace(/^\/api(?=\/|$)/, "") || "/";
  return `${API_BASE_URL}${backendPath}`;
}

export function getStoredAuth() {
  try {
    const value = JSON.parse(localStorage.getItem(AUTH_STORAGE_KEY) || "null");
    return value?.access_token ? value : null;
  } catch {
    return null;
  }
}

export function storeAuth(session) {
  if (!session?.access_token) return;
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
}

export function clearStoredAuth() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
}

export function authHeaders(extra = {}) {
  const session = getStoredAuth();
  return {
    ...extra,
    ...(session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {}),
  };
}
