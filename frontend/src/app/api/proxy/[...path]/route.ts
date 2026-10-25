import { cookies } from "next/headers";
import { API_URL, COOKIE_NAME } from "@/lib/server";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ path: string[] }> };

// Authenticated pass-through to the API: attaches the session cookie's token as a Bearer
// header. The upstream host is fixed (API_INTERNAL_URL), so this cannot be pointed elsewhere.
async function forward(req: Request, ctx: Ctx) {
  const { path } = await ctx.params;
  if (path.some((p) => p === "." || p === "..")) {
    return Response.json({ detail: "Bad path" }, { status: 400 });
  }

  // CSRF defence in depth on top of SameSite=Lax: state-changing calls must be same-origin.
  if (req.method !== "GET") {
    const origin = req.headers.get("origin");
    const host = req.headers.get("host");
    if (origin && host && new URL(origin).host !== host) {
      return Response.json({ detail: "Cross-origin request refused" }, { status: 403 });
    }
  }

  const token = (await cookies()).get(COOKIE_NAME)?.value;
  if (!token) return Response.json({ detail: "Not authenticated" }, { status: 401 });

  const search = new URL(req.url).search;
  const target = `${API_URL}/api/v1/${path.map(encodeURIComponent).join("/")}${search}`;
  const init: RequestInit = {
    method: req.method,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": req.headers.get("content-type") ?? "application/json",
    },
    cache: "no-store",
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    const body = await req.text();
    if (body) init.body = body;
  }

  const upstream = await fetch(target, init);
  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") ?? "application/json",
      ...(upstream.headers.get("content-disposition")
        ? { "content-disposition": upstream.headers.get("content-disposition") as string }
        : {}),
    },
  });
}

export { forward as GET, forward as POST, forward as PATCH, forward as DELETE };
