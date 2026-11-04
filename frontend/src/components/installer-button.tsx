"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";

/** Downloads a one-file Windows installer for a sensor source. Double-click it, accept the
 *  Windows prompt, and the sensor runs in the background and starts with Windows: nothing to type.
 *  Each download makes a new API key (the server stores only a hash), so a sensor already running
 *  with the old key is replaced when the new installer is run. */
export function InstallerButton({
  sourceId,
  sourceName,
  running = false,
  size = "default",
}: {
  sourceId: string;
  sourceName: string;
  /** The source already has a sensor reporting: warn that this replaces its key. */
  running?: boolean;
  size?: "default" | "sm";
}) {
  const [enforce, setEnforce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function download() {
    if (
      running &&
      !window.confirm(
        `"${sourceName}" already has a sensor reporting.\n\nDownloading a new installer gives it a new key: the ` +
          "running sensor stops until you run the new installer on that PC. Continue?",
      )
    ) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/proxy/sources/${encodeURIComponent(sourceId)}/installer`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enforce }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        throw new Error(typeof data?.detail === "string" ? data.detail : `Request failed (${res.status})`);
      }
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = "SentinelBI-sensor-setup.cmd";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setDone(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" size={size} disabled={busy} onClick={download} data-testid="download-installer">
          {busy ? "Preparing…" : "Download installer (Windows)"}
        </Button>
        <label className="flex items-center gap-2 text-xs">
          <input type="checkbox" checked={enforce} onChange={(e) => setEnforce(e.target.checked)} />
          Also block quarantined addresses on that PC
        </label>
      </div>
      {done && (
        <p className="text-sm text-emerald-700 dark:text-emerald-300" role="status">
          Now open the downloaded <strong>SentinelBI-sensor-setup.cmd</strong> on the PC to watch, choose{" "}
          <strong>Yes</strong> when Windows asks, and wait for &quot;Done&quot;. This page turns green when data
          arrives. The file contains the source&apos;s key: do not share it.
        </p>
      )}
      {error && (
        <p className="text-sm text-red-600" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
