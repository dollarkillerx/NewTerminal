// Control-plane HTTP client. The server base is user-configurable (point it at
// your Cloudflare domain, e.g. https://term.example.com) and persisted; ws is
// derived from it (https -> wss).
const DEFAULT_SERVER = "http://127.0.0.1:8799";

export function serverBase(): string {
  return localStorage.getItem("nt_server") || DEFAULT_SERVER;
}
export function setServerBase(url: string) {
  localStorage.setItem("nt_server", url.replace(/\/$/, ""));
}
export function wsUrl(): string {
  return serverBase().replace(/^http/, "ws") + "/ws";
}

async function post(path: string, body: unknown, token?: string) {
  const r = await fetch(serverBase() + path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

export const register = (email: string, password: string) =>
  post("/register", { email, password }) as Promise<{ token: string }>;
export const login = (email: string, password: string) =>
  post("/login", { email, password }) as Promise<{ token: string }>;
export const createTerminal = (token: string, name: string) =>
  post("/terminals", { name }, token) as Promise<{ id: string; name: string }>;
