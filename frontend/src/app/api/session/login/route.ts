import { cookies } from "next/headers";
import { API_URL, COOKIE_NAME, cookieOptions, errorMessage } from "@/lib/server";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  const upstream = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  const data = await upstream.json().catch(() => null);
  if (!upstream.ok) {
    return Response.json(
      { detail: errorMessage(data, "Login failed") },
      { status: upstream.status },
    );
  }
  (await cookies()).set(COOKIE_NAME, data.access_token, cookieOptions());
  return Response.json({ user: data.user });
}
