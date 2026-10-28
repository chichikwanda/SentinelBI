/** Decimal units (kB = 1000 B), as network tools and ISPs count; the backend's reports use the same. */
export function formatBytes(n: number): string {
  if (n < 1000) return `${n} B`;
  const units = ["kB", "MB", "GB", "TB"];
  let v = n / 1000;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat().format(n);
}

export function formatClock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** A time on a chart axis, tooltip or table: the clock alone within a day or so, with the weekday over a
 *  few days and the date beyond a week, so a multi-day graph never shows two different "06:00"s unlabelled. */
export function formatAxisTime(iso: string, spanMs: number): string {
  const d = new Date(iso);
  const hour = { hour: "2-digit", minute: "2-digit" } as const;
  if (spanMs <= 36 * 3600_000) return d.toLocaleTimeString([], hour);
  if (spanMs <= 8 * 86_400_000) return d.toLocaleString([], { weekday: "short", ...hour });
  return d.toLocaleString([], { month: "short", day: "numeric", ...hour });
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Round a maximum up to a "nice" axis end (1, 2, 5 x 10^n). */
export function niceMax(v: number): number {
  if (v <= 0) return 1;
  const pow = 10 ** Math.floor(Math.log10(v));
  const f = v / pow;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * pow;
}
