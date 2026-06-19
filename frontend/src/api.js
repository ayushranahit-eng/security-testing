const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");

export function apiUrl(path) {
  if (!API_BASE_URL) return path;

  const backendPath = path.replace(/^\/api(?=\/|$)/, "") || "/";
  return `${API_BASE_URL}${backendPath}`;
}
