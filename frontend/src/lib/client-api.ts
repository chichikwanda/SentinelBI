// Browser-side API calls. Everything goes through the same-origin BFF (/api/proxy), which
// attaches the session cookie's token, so there is no CORS and no token in JavaScript.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

function detailOf(data: unknown, fallback: string): string {
  const detail = (data as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const msgs = detail.map((d) => (d as { msg?: string }).msg).filter(Boolean);
    if (msgs.length) return msgs.join("; ");
  }
  return fallback;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/proxy/${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (res.status === 401) {
    // session expired or token rejected: clear the cookie and go to login
    await fetch("/api/session/logout", { method: "POST" }).catch(() => undefined);
    // Deliberate full navigation (not router.push): resets all cached query data for the old session.
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, detailOf(data, `Request failed (${res.status})`));
  return data as T;
}

export async function session(kind: "login" | "register", body: unknown): Promise<void> {
  const res = await fetch(`/api/session/${kind}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, detailOf(data, "Something went wrong"));
}
