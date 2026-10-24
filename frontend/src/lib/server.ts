// Server-only helpers for the thin BFF in /api/session and /api/proxy.
// The JWT lives in an httpOnly cookie, so page scripts can never read it.

export const API_URL = process.env.API_INTERNAL_URL ?? "http://127.0.0.1:8000";
export const COOKIE_NAME = "sbi_token";

export function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    // Set COOKIE_SECURE=true when the site is served over HTTPS (production).
    secure: process.env.COOKIE_SECURE === "true",
    path: "/",
    maxAge: 60 * 60, // matches the API's default 60 minute token
  };
}

/** FastAPI returns `detail` as a string or a list of validation errors. */
export function errorMessage(data: unknown, fallback: string): string {
  const detail = (data as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (d as { msg?: string }).msg)
      .filter(Boolean)
      .join("; ") || fallback;
  }
  return fallback;
}
