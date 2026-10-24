"use client";

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";

export function LogoutButton() {
  const router = useRouter();
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={async () => {
        await fetch("/api/session/logout", { method: "POST" });
        router.replace("/login");
      }}
    >
      Sign out
    </Button>
  );
}
