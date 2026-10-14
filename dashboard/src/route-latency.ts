/** Latest successful HTTPS health sample for a currently selected route exit. */
export function routeLatency(status: Record<string, unknown> | null): { ms: number; checkedAt: number; provider: string } | null {
  if (!status?.up || !Array.isArray(status.routes)) return null;
  const providers = status.providers as Record<string, { active?: string; fallback?: { active?: boolean }; egress?: Record<string, { ok?: boolean; latency_ms?: number; checked_at?: number }> }> | undefined;
  const samples = status.routes.flatMap(route => {
    const name = String(route.provider ?? '');
    const provider = providers?.[name];
    if (!provider?.active || provider.fallback?.active) return [];
    const record = provider.egress?.[provider.active];
    if (!record?.ok || typeof record.latency_ms !== 'number' || !Number.isFinite(record.latency_ms)
      || record.latency_ms < 0 || typeof record.checked_at !== 'number' || !Number.isFinite(record.checked_at)) return [];
    return [{ ms: Math.round(record.latency_ms), checkedAt: record.checked_at, provider: name }];
  });
  return samples.sort((a, b) => b.checkedAt - a.checkedAt)[0] ?? null;
}
