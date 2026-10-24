import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { COOKIE_NAME } from "@/lib/server";

export const dynamic = "force-dynamic";

export default async function Home() {
  const signedIn = (await cookies()).has(COOKIE_NAME);
  redirect(signedIn ? "/dashboard" : "/login");
}
