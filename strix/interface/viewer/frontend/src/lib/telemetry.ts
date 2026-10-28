// Best-effort anonymous events. The local server forwards these to PostHog only
// when telemetry is enabled. Never pass PII or scan/report content here.
export function track(event: string, props: Record<string, string | undefined> = {}): void {
  try {
    const body: Record<string, string> = { event };
    for (const [key, value] of Object.entries(props)) {
      if (value !== undefined) body[key] = value;
    }
    const payload = JSON.stringify(body);
    if (typeof navigator !== "undefined" && navigator.sendBeacon) {
      navigator.sendBeacon("/api/event", payload);
    } else {
      void fetch("/api/event", { method: "POST", body: payload, keepalive: true });
    }
  } catch {
    /* telemetry is best-effort */
  }
}
