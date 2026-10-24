import Link from "next/link";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { LogoutButton } from "@/components/logout-button";
import { COOKIE_NAME } from "@/lib/server";

export const dynamic = "force-dynamic";

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  // Cheap gate: the real authorisation happens in the API. An expired/forged token makes the
  // first API call return 401, and the client then clears the cookie and returns to /login.
  if (!(await cookies()).has(COOKIE_NAME)) redirect("/login");

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-black/10 dark:border-white/15">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
          <nav className="flex items-center gap-6 text-sm">
            <Link href="/dashboard" className="text-base font-semibold">
              SentinelBI
            </Link>
            <Link href="/dashboard" className="hover:underline">
              Dashboard
            </Link>
            <Link href="/sources/new" className="hover:underline">
              Add source
            </Link>
          </nav>
          <LogoutButton />
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 space-y-6 px-4 py-6">{children}</main>
    </div>
  );
}
