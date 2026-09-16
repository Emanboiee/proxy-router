import { invoke, isTauri } from '@tauri-apps/api/core';
import fixture from './status.json' with { type: 'json' };

export const states = ['connected', 'disconnected', 'degraded', 'offline', 'stale', 'failed', 'empty', 'loading'] as const;
export type PreviewState = typeof states[number];
export type Connection = 'connected' | 'disconnected' | 'degraded';
export type RouteMode = 'selective' | 'direct' | 'full';
export type FallbackMode = 'direct' | 'retry' | 'block';
export type Scheme = 'system' | 'light' | 'dark';
export type Accent = 'signal' | 'ocean' | 'moss' | 'iris';
export type Density = 'compact' | 'comfortable';
export type LayoutPreset = 'vertical' | 'horizontal';
export type MotionSpeed = 'slow' | 'normal' | 'fast';
export type ProviderKind = 'warp' | 'proton' | 'wireguard' | 'socks5' | 'tailscale' | 'custom';
export type TailscaleMode = 'pause-tailscale' | 'keep-running' | 'prefer-tailscale';

export type ProviderConnection =
  | { kind: 'wireguard'; fileName: string; endpoint: string; interfaceAddress?: string }
  | { kind: 'socks5'; host: string; port: number }
  | { kind: 'tailscale'; exitNode: string };

export interface Status {
  version: 1; source: 'fixture'; connection: 'connected'; profile: string;
  route_mode: 'selective'; router: 'ready'; network: 'online';
  health: string; observed_at: number; stale: boolean; action: 'idle';
}
export interface Profile {
  id: string; name: string; description: string; providerId: string;
  routeMode: RouteMode; domains: string[]; autoSubdomains: boolean; fallback: FallbackMode; updatedAt: number;
}
export interface Provider {
  id: string; name: string; kind: ProviderKind;
  status: 'healthy' | 'degraded' | 'offline'; latency: number | null;
  server: string; servers: string[]; connection?: ProviderConnection;
}
export interface ThemeSettings {
  scheme: Scheme; accent: Accent; density: Density; layout: LayoutPreset; contrast: 'standard' | 'high'; motionSpeed: MotionSpeed; reducedMotion: boolean;
}
export interface Settings {
  launchAtLogin: boolean; closeToTray: boolean; disconnectOnNetworkLoss: boolean;
  autoSwitch: boolean; switchAfterErrors: number; proxyPort: number;
  fullTunnel: boolean; logLevel: 'normal' | 'verbose';
  tailscale: { mode: TailscaleMode };
}
export interface Snapshot {
  connection: Connection; network: 'online' | 'offline'; activeProfileId: string | null;
  profiles: Profile[]; providers: Provider[]; settings: Settings; theme: ThemeSettings;
  logs: string[]; lastAction: string;
}

const STORAGE_KEY = 'proxy-router.dashboard.state.v2';
const now = () => Date.now();
const id = (prefix: string) => `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
const defaultState: Snapshot = {
  connection: 'disconnected', network: 'online', activeProfileId: 'school',
  profiles: [
    { id: 'school', name: 'School access', description: 'Blocked sites through a resilient provider.', providerId: 'warp', routeMode: 'selective', domains: ['discord.com', 'twitch.tv', 'static.twitchcdn.net'], autoSubdomains: false, fallback: 'direct', updatedAt: now() },
    { id: 'opencode', name: 'OpenCode only', description: 'Keep the rest of the computer on the normal connection.', providerId: 'proton', routeMode: 'selective', domains: ['opencode.ai', 'api.opencode.ai'], autoSubdomains: false, fallback: 'retry', updatedAt: now() },
    { id: 'direct', name: 'Direct connection', description: 'No routed sites; useful at home or on trusted Wi-Fi.', providerId: 'warp', routeMode: 'direct', domains: [], autoSubdomains: false, fallback: 'direct', updatedAt: now() },
  ],
  providers: [
    { id: 'warp', name: 'Cloudflare WARP', kind: 'warp', status: 'healthy', latency: 42, server: 'Automatic', servers: ['Automatic', 'Los Angeles', 'Singapore', 'Tokyo'] },
    { id: 'proton', name: 'Proton VPN', kind: 'proton', status: 'healthy', latency: 68, server: '15-US-FREE-36', servers: ['15-US-FREE-36', '22-SG-FREE-15', '30-NL-FREE-21'] },
    { id: 'wireguard', name: 'WireGuard', kind: 'wireguard', status: 'degraded', latency: 112, server: 'wg-no-free-9', servers: ['wg-no-free-9', 'wg-no-free-12'] },
  ],
  settings: { launchAtLogin: false, closeToTray: true, disconnectOnNetworkLoss: true, autoSwitch: true, switchAfterErrors: 5, proxyPort: 2080, fullTunnel: false, logLevel: 'normal', tailscale: { mode: 'pause-tailscale' } },
  theme: { scheme: 'dark', accent: 'signal', density: 'compact', layout: 'horizontal', contrast: 'standard', motionSpeed: 'normal', reducedMotion: false },
  logs: ['Dashboard ready', 'Profile “School access” selected', 'Selective routing is active'], lastAction: 'Ready',
};
function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function storage(): Storage | null { try { return typeof localStorage === 'undefined' ? null : localStorage; } catch { return null; } }

export function parseWireGuardConfig(raw: string, fileName = 'wireguard.conf'): ProviderConnection & { kind: 'wireguard' } {
  if (!raw.trim() || raw.length > 128 * 1024) throw new Error('Choose a non-empty WireGuard configuration under 128 KB');
  const interfaceBlock = raw.match(/\[Interface\]([\s\S]*?)(?=\n\s*\[|$)/i)?.[1] ?? '';
  const peerBlock = raw.match(/\[Peer\]([\s\S]*?)(?=\n\s*\[|$)/i)?.[1] ?? '';
  const value = (block: string, key: string) => block.match(new RegExp(`^\\s*${key}\\s*=\\s*([^#\\r\\n]+)`, 'im'))?.[1]?.trim();
  if (!interfaceBlock || !peerBlock || !value(interfaceBlock, 'PrivateKey') || !value(peerBlock, 'PublicKey') || !value(peerBlock, 'Endpoint')) {
    throw new Error('WireGuard config needs [Interface] PrivateKey and [Peer] PublicKey/Endpoint');
  }
  const endpoint = value(peerBlock, 'Endpoint')!;
  const interfaceAddress = value(interfaceBlock, 'Address');
  return { kind: 'wireguard', fileName: fileName.trim() || 'wireguard.conf', endpoint, ...(interfaceAddress ? { interfaceAddress } : {}) };
}

export class LocalController {
  private data: Snapshot;
  constructor() {
    const saved = storage()?.getItem(STORAGE_KEY);
    try {
      const initial = saved ? this.validate(JSON.parse(saved)) : clone(defaultState);
      // A saved UI snapshot is not proof that the router is still connected after relaunch.
      this.data = { ...initial, connection: 'disconnected' };
    } catch { this.data = clone(defaultState); }
    storage()?.setItem(STORAGE_KEY, JSON.stringify(this.data));
  }
  private validate(value: unknown): Snapshot {
    if (!value || typeof value !== 'object') throw new Error('Invalid saved state');
    const candidate = value as Partial<Snapshot>;
    if (!Array.isArray(candidate.profiles) || !Array.isArray(candidate.providers) || !candidate.settings || !candidate.theme) throw new Error('Invalid saved state');
    const profiles = candidate.profiles.map(profile => ({ ...profile, autoSubdomains: profile.autoSubdomains === true }));
    const savedTailscale = (candidate.settings as Partial<Settings>).tailscale;
    const savedLayout = candidate.theme.layout;
    const layout = savedLayout === 'vertical' || savedLayout === 'horizontal' ? savedLayout : defaultState.theme.layout;
    return { ...clone(defaultState), ...clone(candidate), profiles, settings: { ...clone(defaultState.settings), ...candidate.settings, tailscale: { mode: savedTailscale?.mode ?? defaultState.settings.tailscale.mode } }, theme: { ...clone(defaultState.theme), ...candidate.theme, layout } };
  }
  snapshot(): Snapshot { return clone(this.data); }
  private commit(message: string): Snapshot {
    this.data.lastAction = message; this.data.logs = [message, ...this.data.logs].slice(0, 30);
    storage()?.setItem(STORAGE_KEY, JSON.stringify(this.data)); return this.snapshot();
  }
  private async settle(message: string): Promise<Snapshot> { return this.commit(message); }
  async connect(): Promise<Snapshot> { this.data.connection = 'connected'; return this.settle('Connected'); }
  async disconnect(): Promise<Snapshot> { this.data.connection = 'disconnected'; return this.settle('Disconnected'); }
  async reconnect(): Promise<Snapshot> { this.data.connection = 'connected'; return this.settle('Reconnected using the healthiest provider'); }
  async selectProfile(profileId: string): Promise<Snapshot> {
    if (!this.data.profiles.some(profile => profile.id === profileId)) throw new Error('Profile not found');
    this.data.activeProfileId = profileId; return this.settle(`Profile “${this.data.profiles.find(profile => profile.id === profileId)?.name}” selected`);
  }
  async saveProfile(input: Omit<Profile, 'id' | 'updatedAt'>, profileId?: string): Promise<Snapshot> {
    const name = input.name.trim(); if (!name) throw new Error('Give this profile a name');
    const domains = [...new Set(input.domains.map(domain => domain.trim().toLowerCase()).filter(Boolean))];
    const autoSubdomains = input.autoSubdomains === true;
    if (profileId) { const profile = this.data.profiles.find(item => item.id === profileId); if (!profile) throw new Error('Profile not found'); Object.assign(profile, { ...input, name, domains, autoSubdomains, updatedAt: now() }); return this.settle(`Profile “${name}” updated`); }
    const profile = { ...input, id: id('profile'), name, domains, autoSubdomains, updatedAt: now() }; this.data.profiles.push(profile); this.data.activeProfileId = profile.id; return this.settle(`Profile “${name}” created`);
  }
  async duplicateProfile(profileId: string): Promise<Snapshot> { const source = this.data.profiles.find(profile => profile.id === profileId); if (!source) throw new Error('Profile not found'); return this.saveProfile({ ...clone(source), name: `${source.name} copy` }); }
  async deleteProfile(profileId: string): Promise<Snapshot> {
    if (this.data.profiles.length <= 1) throw new Error('Keep at least one profile'); const removed = this.data.profiles.find(profile => profile.id === profileId);
    this.data.profiles = this.data.profiles.filter(profile => profile.id !== profileId); if (this.data.activeProfileId === profileId) this.data.activeProfileId = this.data.profiles[0].id; return this.settle(`Profile “${removed?.name ?? 'Profile'}” deleted`);
  }
  async addDomain(domain: string): Promise<Snapshot> { const profile = this.activeProfile(); const value = domain.trim().toLowerCase(); if (!value || !value.includes('.')) throw new Error('Enter a domain such as twitch.tv'); if (!profile.domains.includes(value)) profile.domains.push(value); profile.updatedAt = now(); return this.settle(`Added ${value} to ${profile.name}`); }
  async removeDomain(domain: string): Promise<Snapshot> { const profile = this.activeProfile(); profile.domains = profile.domains.filter(item => item !== domain); profile.updatedAt = now(); return this.settle(`Removed ${domain}`); }
  async applyPreset(mode: RouteMode, domains: string[] = []): Promise<Snapshot> { const profile = this.activeProfile(); profile.routeMode = mode; if (domains.length) profile.domains = [...new Set(domains)]; profile.updatedAt = now(); return this.settle(`${mode === 'selective' ? 'Selective routing' : mode === 'full' ? 'Full tunnel' : 'Direct connection'} preset applied`); }
  async setFallback(fallback: FallbackMode): Promise<Snapshot> { const profile = this.activeProfile(); profile.fallback = fallback; profile.updatedAt = now(); return this.settle(`Fallback set to ${fallback}`); }
  async setProvider(providerId: string): Promise<Snapshot> { const profile = this.activeProfile(); const provider = this.data.providers.find(item => item.id === providerId); if (!provider) throw new Error('Provider not found'); profile.providerId = providerId; profile.updatedAt = now(); return this.settle(`${provider.name} selected`); }
  async addProvider(input: { name: string; kind: ProviderKind; server: string; connection?: ProviderConnection }): Promise<Snapshot> {
    const name = input.name.trim(); const server = input.server.trim(); if (!name) throw new Error('Give this provider a name'); if (!server) throw new Error('Add a server or endpoint');
    const provider: Provider = { id: id('provider'), name, kind: input.kind, status: 'healthy', latency: null, server, servers: [server], ...(input.connection ? { connection: input.connection } : {}) }; this.data.providers.push(provider); return this.settle(`${name} added`);
  }
  async importProviderConfig(input: { name: string; kind: 'wireguard' | 'custom'; fileName: string; raw: string }): Promise<Snapshot> {
    const connection = parseWireGuardConfig(input.raw, input.fileName);
    return this.addProvider({ name: input.name, kind: input.kind, server: connection.endpoint, connection });
  }
  async addSocks5Provider(input: { name: string; host: string; port: string | number }): Promise<Snapshot> {
    const host = input.host.trim(); const port = Number(input.port);
    if (!host) throw new Error('Add the SOCKS5 host');
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Use a SOCKS5 port from 1 to 65535');
    const connection: ProviderConnection = { kind: 'socks5', host, port };
    return this.addProvider({ name: input.name, kind: 'socks5', server: `${host}:${port}`, connection });
  }
  async addTailscaleProvider(input: { name: string; exitNode: string }): Promise<Snapshot> {
    const exitNode = input.exitNode.trim();
    if (!exitNode) throw new Error('Add a Tailscale exit node name or address');
    if (exitNode.length > 255) throw new Error('Use a Tailscale exit node under 255 characters');
    const connection: ProviderConnection = { kind: 'tailscale', exitNode };
    return this.addProvider({ name: input.name, kind: 'tailscale', server: exitNode, connection });
  }
  async setServer(providerId: string, server: string): Promise<Snapshot> { const provider = this.data.providers.find(item => item.id === providerId); if (!provider || !provider.servers.includes(server)) throw new Error('Server not found'); provider.server = server; return this.settle(`${provider.name} server changed to ${server}`); }
  async refreshHealth(): Promise<Snapshot> { this.data.providers = this.data.providers.map(provider => ({ ...provider, status: 'healthy', latency: provider.id === 'warp' ? 42 : provider.id === 'proton' ? 68 : 96 })); return this.settle('Provider health refreshed'); }
  async simulateOutage(providerId: string, offline: boolean): Promise<Snapshot> { const provider = this.data.providers.find(item => item.id === providerId); if (!provider) throw new Error('Provider not found'); provider.status = offline ? 'offline' : 'healthy'; if (offline && this.activeProfile().providerId === providerId) this.data.connection = 'degraded'; return this.settle(offline ? `${provider.name} marked unavailable` : `${provider.name} recovered`); }
  async updateSettings(patch: Partial<Settings>): Promise<Snapshot> { this.data.settings = { ...this.data.settings, ...patch }; return this.settle('Settings saved'); }
  async updateTailscale(patch: Partial<Settings['tailscale']>): Promise<Snapshot> { this.data.settings.tailscale = { ...this.data.settings.tailscale, ...patch }; return this.settle('Tailscale settings saved'); }
  async updateTheme(patch: Partial<ThemeSettings>): Promise<Snapshot> { this.data.theme = { ...this.data.theme, ...patch }; return this.settle('Appearance saved'); }
  activeProfile(): Profile { return this.data.profiles.find(profile => profile.id === this.data.activeProfileId) ?? this.data.profiles[0]; }
  exportProfile(profileId = this.data.activeProfileId): string { const profile = this.data.profiles.find(item => item.id === profileId); if (!profile) throw new Error('Profile not found'); return JSON.stringify({ proxyRouterProfile: 1, profile }, null, 2); }
  async importProfile(raw: string): Promise<Snapshot> { const value = JSON.parse(raw) as { proxyRouterProfile?: number; profile?: Partial<Omit<Profile, 'id' | 'updatedAt'>> }; const profile = value.profile; const name = profile?.name; if (value.proxyRouterProfile !== 1 || !profile || typeof name !== 'string') throw new Error('This is not a proxy-router profile export'); return this.saveProfile({ name, description: profile.description ?? '', fallback: profile.fallback ?? 'direct', routeMode: profile.routeMode ?? 'selective', domains: profile.domains ?? [], autoSubdomains: profile.autoSubdomains ?? false, providerId: profile.providerId ?? 'warp' }); }
  reset(): Snapshot { this.data = clone(defaultState); storage()?.setItem(STORAGE_KEY, JSON.stringify(this.data)); return this.snapshot(); }
}

export function parseStatus(value: unknown): Status {
  if (!value || typeof value !== 'object') throw new Error('Invalid status'); const s = value as Record<string, unknown>;
  if (s.version !== 1 || s.source !== 'fixture' || s.connection !== 'connected' || s.route_mode !== 'selective' || s.router !== 'ready' || s.network !== 'online' || s.action !== 'idle' || typeof s.profile !== 'string' || typeof s.health !== 'string' || typeof s.stale !== 'boolean' || typeof s.observed_at !== 'number' || !Number.isFinite(s.observed_at)) throw new Error('Invalid status');
  return s as unknown as Status;
}
export async function getPreviewStatus(): Promise<Status> {
  let timer: ReturnType<typeof setTimeout> | undefined; try { const request = isTauri() ? invoke<unknown>('get_preview_status') : Promise.resolve(fixture); const result = await Promise.race([request, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Status timeout')), 3000); })]); return parseStatus(result); } finally { clearTimeout(timer); }
}
export function setTrayStatus(state: PreviewState): void {
  if (isTauri()) void invoke('set_tray_status', { state }).catch(() => {});
}

export interface LiveStatus {
  state: PreviewState;
  status: Record<string, unknown> | null;
}

/**
 * Real controller reading from the desktop app (`router.py status --json`).
 *
 * The build-time fixture above only backs the browser preview; the tray and
 * the connection state must follow the actual router (#144).
 */
export async function getLiveStatus(): Promise<LiveStatus> {
  if (!isTauri()) throw new Error('Live status requires the desktop app');
  return await invoke<LiveStatus>('get_live_status');
}
/** Engine verbs the desktop app may run (mirrors the Rust allowlist). */
export type EngineAction = 'connect' | 'disconnect' | 'reconnect';

/** Preset each built-in profile maps to in the real router config. */
const PROFILE_PRESET: Record<string, string> = {
  opencode: 'opencode',
  school: 'school-warp',
};

/**
 * Run a real engine verb from the window.
 *
 * The prototype controller only flipped browser-local state, so a Disconnect
 * looked like it reverted as soon as the next live poll landed.
 */
export async function applyEngineAction(action: EngineAction): Promise<void> {
  if (!isTauri()) return;
  await invoke('run_router_action', { action });
}

/**
 * Apply the real routing for a profile choice.
 *
 * `direct` stops the engine (no routed sites); the other built-in profiles
 * apply their matching preset. Unknown profiles stay local-only.
 */
export async function applyProfileToEngine(profileId: string): Promise<void> {
  if (!isTauri()) return;
  if (profileId === 'direct') {
    await invoke('run_router_action', { action: 'disconnect' });
    return;
  }
  const preset = PROFILE_PRESET[profileId];
  if (preset) await invoke('apply_preset', { name: preset });
}

/** Redacted router.json view (allowlisted keys only). */
export interface EngineConfig {
  port?: number;
  preset?: string;
  providers?: Record<string, Record<string, unknown>>;
  routes?: Array<Record<string, unknown>>;
  routing?: Record<string, unknown>;
  vpn?: Record<string, unknown>;
  keepalive?: Record<string, unknown>;
  rotation?: Record<string, unknown>;
}

/** Network detection: current Wi-Fi plus the SSID -> preset map. */
export interface NetworkPresetState {
  ssid: string | null;
  connected: boolean;
  auto: boolean;
  mapped_preset: string | null;
  presets: Record<string, string>;
  last_applied: Record<string, unknown>;
}

/** Presets the dashboard may map a network to (mirrors the engine built-ins). */
export const presetChoices = ['opencode', 'school-warp', 'roblox', 'default'] as const;

export async function getConfig(): Promise<EngineConfig> {
  if (!isTauri()) throw new Error('Live config requires the desktop app');
  return await invoke<EngineConfig>('get_config');
}

export async function getNetwork(): Promise<{ status: Record<string, unknown>; presets: NetworkPresetState }> {
  if (!isTauri()) throw new Error('Network detection requires the desktop app');
  return await invoke<{ status: Record<string, unknown>; presets: NetworkPresetState }>('get_network');
}

export async function setNetworkPreset(ssid: string, preset: string): Promise<NetworkPresetState> {
  return await invoke<NetworkPresetState>('set_network_preset', { ssid, preset });
}

export async function removeNetworkPreset(ssid: string): Promise<NetworkPresetState> {
  return await invoke<NetworkPresetState>('remove_network_preset', { ssid });
}

export async function setNetworkAuto(state: 'on' | 'off'): Promise<NetworkPresetState> {
  return await invoke<NetworkPresetState>('set_network_auto', { state });
}

/** Recovery verbs owned by the engine (no UI-side policy). */
export async function runNetworkAction(action: 'network-check' | 'network-reconnect' | 'network-disconnect'): Promise<void> {
  if (!isTauri()) return;
  await invoke('run_router_action', { action });
}

export function reportPreviewFrame(): void { if (isTauri()) void invoke('preview_rendered').catch(() => {}); }
