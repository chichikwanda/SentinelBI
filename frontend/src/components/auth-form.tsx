"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { session } from "@/lib/client-api";

export function AuthForm({ mode }: { mode: "login" | "register" }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isRegister = mode === "register";

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      await session(
        mode,
        isRegister
          ? { org_name: form.get("org_name"), email: form.get("email"), password: form.get("password") }
          : { email: form.get("email"), password: form.get("password") },
      );
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
      setBusy(false);
    }
  }

  return (
    <main className="flex flex-1 items-center justify-center p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>{isRegister ? "Create your organisation" : "Sign in to SentinelBI"}</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4">
            {isRegister && (
              <div>
                <Label htmlFor="org_name">Organisation name</Label>
                <Input id="org_name" name="org_name" required minLength={2} autoComplete="organization" />
              </div>
            )}
            <div>
              <Label htmlFor="email">Email</Label>
              <Input id="email" name="email" type="email" required autoComplete="email" />
            </div>
            <div>
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                required
                minLength={isRegister ? 10 : 1}
                autoComplete={isRegister ? "new-password" : "current-password"}
              />
              {isRegister && <p className="mt-1 text-xs text-black/55 dark:text-white/55">At least 10 characters.</p>}
            </div>
            {error && (
              <p role="alert" className="text-sm text-red-600 dark:text-red-400">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Please wait…" : isRegister ? "Create account" : "Sign in"}
            </Button>
          </form>
          <p className="mt-4 text-center text-sm">
            {isRegister ? (
              <>
                Already registered? <Link className="text-blue-600 underline" href="/login">Sign in</Link>
              </>
            ) : (
              <>
                New organisation? <Link className="text-blue-600 underline" href="/register">Register</Link>
              </>
            )}
          </p>
        </CardContent>
      </Card>
    </main>
  );
}
