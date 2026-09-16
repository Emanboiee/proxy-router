import './tokens.css';
import './style.css';
import { LocalController, applyEngineAction, applyProfileToEngine, getLiveStatus, getPreviewStatus, reportPreviewFrame, setTrayStatus, states, type Accent, type Connection, type Density, type FallbackMode, type LayoutPreset, type MotionSpeed, type PreviewState, type Profile, type ProviderKind, type RouteMode, type Scheme, type Snapshot, type Status, type TailscaleMode } from './controller';
import { isTauri } from '@tauri-apps/api/core';

const pages = ['Home', 'Profiles', 'Providers', 'Connectivity', 'Settings', 'Appearance', 'About'] as const;
type Page = typeof pages[number];
const controller = new LocalController();
let snapshot = controller.snapshot();
let status: Status | null = null;
let previewState: PreviewState = snapshot.connection;
let page: Page = 'Home';
let editingProfileId: string | undefined;
let addingProvider = false;
let addingProviderFromProfile = false;
let pendingProviderId: string | undefined;
let profileDraft: Omit<Profile, 'id' | 'updatedAt'> | undefined;
let providerReturnFocusContext: 'providers' | 'profile' | undefined;
let requestGeneration = 0;
let busy = false;
let actionQueue: Promise<void> = Promise.resolve();
let lastTrayState: PreviewState | undefined;
const app = document.querySelector<HTMLDivElement>('#app')!;

const copy: Record<PreviewState, [string, string]> = {
  connected: ['Connected', 'Proxied traffic is protected.'],
  disconnected: ['Disconnected', 'Traffic is using your normal connection.'],
  degraded: ['Needs attention', 'Connected with a route that needs attention.'],
  offline: ['Network unavailable', 'Waiting for a usable network.'],
  stale: ['Status is out of date', 'The last result is no longer current. Refresh before relying on it.'],
  failed: ['Couldn’t read status', 'The local controller did not answer. Retry to check again.'],
  empty: ['Make it yours', 'A profile brings your selected sites and connection settings together.'],
  loading: ['Checking status', 'Waiting for the local controller…'],
};
const accents: { id: Accent; name: string; colour: string }[] = [
  { id: 'signal', name: 'Signal', colour: '#ff9c66' }, { id: 'ocean', name: 'Ocean', colour: '#8bc7ff' },
  { id: 'moss', name: 'Moss', colour: '#a8ddb0' }, { id: 'iris', name: 'Iris', colour: '#c9b7ff' },
];

app.innerHTML = `<aside class="rail"><header><img class="rail-logo" src="/gremlin-cat-goblin-cat.gif" alt="" width="32" height="32" decoding="async"><strong>proxy router</strong><button id="menu" aria-expanded="false" aria-controls="nav">Menu</button></header><nav id="nav" aria-label="Primary">${pages.map(item => `<a href="#${item.toLowerCase()}">${item}</a>`).join('')}</nav><div class="rail-status"><span class="status-dot" aria-hidden="true"></span><span id="rail-status">Local controller</span></div></aside><div class="workspace"><div class="topbar" role="banner"><span id="page-label">Home</span><span class="topbar-actions"><span class="badge">Local prototype</span><span id="toast" role="status" aria-live="polite"></span></span></div><main id="main" tabindex="-1"></main><footer><span>Local data · router changes stay behind the controller</span><button id="preview" type="button">Preview states</button></footer></div><dialog id="preview-dialog" aria-labelledby="dialog-title"><form method="dialog"><h2 id="dialog-title">Preview a connection state</h2><p>These examples review the interface. They do not change your network or VPN.</p><label for="scenario">Connection state</label><select id="scenario">${states.map(item => `<option value="${item}">${copy[item][0]}</option>`).join('')}</select><div class="dialog-actions"><button value="cancel" autofocus>Cancel</button><button value="apply" class="primary">Show preview</button></div></form></dialog><dialog id="import-dialog" aria-labelledby="import-title"><form id="import-form" method="dialog"><h2 id="import-title">Import a profile</h2><p>Paste a proxy-router profile export. It is saved locally on this computer.</p><label for="profile-json">Profile JSON</label><textarea id="profile-json" rows="8" required placeholder="{ &quot;proxyRouterProfile&quot;: 1, &quot;profile&quot;: ... }"></textarea><div class="dialog-actions"><button value="cancel">Cancel</button><button value="import" class="primary">Import profile</button></div></form></dialog><dialog id="profile-dialog" aria-labelledby="profile-dialog-title"></dialog><dialog id="provider-dialog" aria-labelledby="provider-dialog-title"></dialog>`;
const main = document.querySelector<HTMLElement>('#main')!;
const previewDialog = document.querySelector<HTMLDialogElement>('#preview-dialog')!;
const importDialog = document.querySelector<HTMLDialogElement>('#import-dialog')!;
const profileDialog = document.querySelector<HTMLDialogElement>('#profile-dialog')!;
const providerDialog = document.querySelector<HTMLDialogElement>('#provider-dialog')!;
const scenario = document.querySelector<HTMLSelectElement>('#scenario')!;
const menu = document.querySelector<HTMLButtonElement>('#menu')!;

function esc(value: string): string { return value.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character] ?? character)); }
function activeProfile(): Profile { return controller.activeProfile(); }
function activeProvider() { return snapshot.providers.find(item => item.id === activeProfile().providerId) ?? snapshot.providers[0]; }
function announce(message: string): void { const toast = document.querySelector('#toast')!; toast.textContent = message; window.setTimeout(() => { if (toast.textContent === message) toast.textContent = ''; }, 2600); const region = document.querySelector('#announcement')!; region.textContent = message; }
function applyTheme(): void {
  const root = document.documentElement;
  root.dataset.scheme = snapshot.theme.scheme; root.dataset.accent = snapshot.theme.accent; root.dataset.density = snapshot.theme.density; root.dataset.layout = snapshot.theme.layout; root.dataset.contrast = snapshot.theme.contrast; root.dataset.motionSpeed = snapshot.theme.motionSpeed; root.dataset.motion = snapshot.theme.reducedMotion ? 'reduced' : 'full';
  root.style.colorScheme = snapshot.theme.scheme === 'system' ? 'light dark' : snapshot.theme.scheme;
}
function sync(next: Snapshot, message = next.lastAction): void { snapshot = next; if (!isTauri() && previewState !== 'loading') previewState = snapshot.connection; applyTheme(); render(); if (message) announce(message); }
function perform(action: () => Promise<Snapshot>): Promise<void> { actionQueue = actionQueue.then(async () => { busy = true; try { sync(await action()); } catch (error) { announce(error instanceof Error ? error.message : 'Action failed'); } finally { busy = false; render(); } }); return actionQueue; }
function button(label: string, action: string, className = '', extra = ''): string { return `<button type="button" class="${className}" data-action="${action}" ${extra} ${busy ? 'disabled' : ''}>${label}</button>`; }
function statusTitle(): [string, string] { return copy[previewState]; }
function providerOptions(selected: string): string { return snapshot.providers.map(provider => `<option value="${provider.id}" ${provider.id === selected ? 'selected' : ''}>${esc(provider.name)}</option>`).join(''); }
function profileOptions(selected: string | null): string { return snapshot.profiles.map(profile => `<option value="${profile.id}" ${profile.id === selected ? 'selected' : ''}>${esc(profile.name)}</option>`).join(''); }
function routeLabel(mode: RouteMode): string { return mode === 'full' ? 'Full tunnel' : mode === 'direct' ? 'Direct connection' : 'Selective routing'; }
function fallbackLabel(mode: FallbackMode): string { return mode === 'direct' ? 'Direct fallback' : mode === 'retry' ? 'Retry another provider' : 'Block until healthy'; }

function profileMenuOptions(selected: string | null): string {
  return snapshot.profiles.map(profile => `<button type="button" role="option" aria-selected="${profile.id === selected}" data-profile-option="${esc(profile.id)}"><span>${esc(profile.name)}</span>${profile.id === selected ? '<span class="option-check" aria-hidden="true">✓</span>' : ''}</button>`).join('');
}

function profileMenu(trigger: HTMLElement, open: boolean, focusSelected = false): void {
  const menuId = trigger.getAttribute('aria-controls');
  const menu = menuId ? document.getElementById(menuId) : null;
  if (!menu) return;
  trigger.setAttribute('aria-expanded', String(open));
  menu.toggleAttribute('hidden', !open);
  if (open && focusSelected) menu.querySelector<HTMLElement>('[aria-selected="true"]')?.focus();
}

function profileMenuTriggerFor(target: Element): HTMLElement | null {
  return target.closest<HTMLElement>('[data-profile-trigger]');
}

function closeProfileMenus(except?: HTMLElement): void {
  document.querySelectorAll<HTMLElement>('[data-profile-trigger][aria-expanded="true"]').forEach(trigger => {
    if (trigger !== except) profileMenu(trigger, false);
  });
}

function moveProfileOption(trigger: HTMLElement, direction: number): void {
  const menuId = trigger.getAttribute('aria-controls');
  const menu = menuId ? document.getElementById(menuId) : null;
  const options = menu ? [...menu.querySelectorAll<HTMLElement>('[data-profile-option]')] : [];
  if (!options.length) return;
  const current = options.indexOf(document.activeElement as HTMLElement);
  const selected = options.findIndex(option => option.getAttribute('aria-selected') === 'true');
  const index = current >= 0 ? current : selected >= 0 ? selected : 0;
  options[(index + direction + options.length) % options.length].focus();
}

function homePage(): string {
  const [title, description] = statusTitle(); const profile = activeProfile(); const provider = activeProvider();
  const action = previewState === 'connected' ? button('Disconnect', 'disconnect', 'danger') : previewState === 'disconnected' ? button('Connect', 'connect', 'primary') : previewState === 'failed' || previewState === 'stale' ? button('Refresh preview', 'refresh', 'primary') : button('Reconnect', 'reconnect', 'primary');
  const routeInfo = profile.routeMode === 'selective' ? `${profile.domains.length} ${profile.domains.length === 1 ? 'site' : 'sites'}` : routeLabel(profile.routeMode);
  const compactStatus = `${provider.name} · ${provider.latency ?? '—'} ms · ${routeInfo} · ${fallbackLabel(profile.fallback)}`;
  return `<section class="page-section home-page" data-state="${previewState}">
    <div class="connection-hero">
      <div class="connection-emblem" aria-hidden="true"><img src="/gremlin-cat-goblin-cat.gif" alt="" width="220" height="242" decoding="async"></div>
      <h1 tabindex="-1">${title}</h1>
      <p class="lead">${description}</p>
      <div class="hero-actions">${action}</div>
      <div class="mode-selector" data-profile-picker><span id="home-profile-label">Mode</span><span class="select-wrap custom-select"><button type="button" role="combobox" class="select-trigger" id="home-profile" data-profile-trigger aria-labelledby="home-profile-label" aria-haspopup="listbox" aria-expanded="false" aria-controls="home-profile-options"><span class="select-value">${esc(profile.name)}</span><span class="select-chevron" aria-hidden="true"></span></button><div class="select-menu" id="home-profile-options" role="listbox" aria-labelledby="home-profile-label" hidden>${profileMenuOptions(snapshot.activeProfileId)}</div></span></div>
      <p class="connection-status" aria-label="Connection status"><span>${esc(compactStatus)}</span><a class="text-link" href="#profiles">Edit profile <span aria-hidden="true">↗</span></a></p>
    </div>
  </section>`;
}

function profileForm(profile?: Profile): string {
  const value = profileDraft ?? profile ?? { name: '', description: '', providerId: activeProvider().id, routeMode: 'selective' as RouteMode, domains: [] as string[], autoSubdomains: false, fallback: 'direct' as FallbackMode };
  const selectedProviderId = pendingProviderId ?? value.providerId;
  return `<form class="panel editor profile-editor" id="profile-form"><div class="panel-heading"><div><span class="label">${profile ? 'Edit profile' : 'New profile'}</span><h2 id="profile-dialog-title">${profile ? esc(profile.name) : 'Create a profile'}</h2></div><button type="button" class="quiet" data-action="cancel-profile">← Back</button></div><div class="form-grid"><label>Name<input id="profile-name" name="name" required maxlength="48" value="${esc(value.name)}" placeholder="e.g. School access"></label><div class="field-with-action"><label>Connection<select name="providerId">${providerOptions(selectedProviderId)}</select></label><button type="button" class="quiet" data-action="new-provider-from-profile">Add connection</button></div><label class="wide">Description<input name="description" maxlength="120" value="${esc(value.description)}" placeholder="What is this profile for?"></label><div class="wide form-subsection"><span class="label">Traffic routing</span><p class="muted">Choose where this profile sends traffic and what happens when its route fails.</p></div><label>Routing mode<select name="routeMode"><option value="selective" ${value.routeMode === 'selective' ? 'selected' : ''}>Selective routing</option><option value="direct" ${value.routeMode === 'direct' ? 'selected' : ''}>Direct connection</option><option value="full" ${value.routeMode === 'full' ? 'selected' : ''}>Full tunnel</option></select></label><label>Fallback<select name="fallback"><option value="direct" ${value.fallback === 'direct' ? 'selected' : ''}>Fall back to direct</option><option value="retry" ${value.fallback === 'retry' ? 'selected' : ''}>Retry another provider</option><option value="block" ${value.fallback === 'block' ? 'selected' : ''}>Block until healthy</option></select></label><label class="wide">Domains <span class="muted">one per line</span><textarea id="profile-domains" name="domains" rows="4" placeholder="example.com&#10;api.example.com">${esc(value.domains.join('\n'))}</textarea><span class="field-note">Enter the domains this profile should route. Turn on subdomain detection to include everything under each domain.</span></label><label class="setting-row wide"><span><strong>Auto-detect subdomains</strong><small>Route subdomains under each domain in this profile automatically.</small></span><input type="checkbox" name="autoSubdomains" ${value.autoSubdomains ? 'checked' : ''}></label></div><div class="form-actions"><button type="submit" class="primary">${profile ? 'Save changes' : 'Create profile'}</button></div></form>`;
}

function profilesPage(): string {
  const cards = snapshot.profiles.map(profile => `<article class="profile-card ${profile.id === snapshot.activeProfileId ? 'selected' : ''}"><div class="panel-heading"><div><span class="label">${profile.id === snapshot.activeProfileId ? 'Active profile' : 'Profile'}</span><h2>${esc(profile.name)}</h2></div></div><p class="muted">${esc(profile.description || 'No description yet.')}</p><div class="profile-meta"><span>${profile.routeMode === 'full' ? 'Full tunnel' : profile.routeMode === 'direct' ? 'Direct' : `${profile.domains.length} routed sites`}</span><span>${profile.autoSubdomains ? 'Subdomains on' : 'Exact domains'}</span><span>${fallbackLabel(profile.fallback)}</span><span>${esc(snapshot.providers.find(provider => provider.id === profile.providerId)?.name ?? 'Provider')}</span></div><div class="card-actions">${profile.id === snapshot.activeProfileId ? '' : button('Use profile', 'select-profile', 'primary', `data-profile="${profile.id}"`)}${button('Edit', 'edit-profile', 'quiet', `data-profile="${profile.id}"`)}${button('Duplicate', 'duplicate-profile', 'quiet', `data-profile="${profile.id}"`)}${button('Export', 'export-profile', 'quiet', `data-profile="${profile.id}"`)}${button('Delete', 'delete-profile', 'quiet danger-text', `data-profile="${profile.id}"`)}</div></article>`).join('');
  return `<section class="page-section"><div class="section-heading"><div><h1 tabindex="-1">Profiles</h1><p class="lead">Create a profile, add its connection, and keep routing and fallback choices together.</p></div><div class="section-actions">${button('Create profile', 'new-profile', 'primary')}${button('Import', 'import-profile', 'quiet')}</div></div><div class="cards profile-cards">${cards}</div><article class="panel tip"><strong>Profiles are independent.</strong><span>Switching one changes the next connection action; it never edits another profile.</span></article></section>`;
}

function providerKindLabel(kind: ProviderKind): string { return kind === 'warp' ? 'Cloudflare WARP' : kind === 'proton' ? 'Proton VPN' : kind === 'wireguard' ? 'WireGuard' : kind === 'socks5' ? 'SOCKS5 proxy' : kind === 'tailscale' ? 'Tailscale exit node' : 'Custom VPN'; }
function tailscaleModeLabel(mode: TailscaleMode): string { return mode === 'pause-tailscale' ? 'Pause Tailscale while a VPN is active' : mode === 'prefer-tailscale' ? 'Prefer Tailscale when it is active' : 'Keep Tailscale running'; }
function providerForm(context: 'providers' | 'profile' = 'providers'): string {
  const fromProfile = context === 'profile';
  return `<form class="panel editor provider-editor" id="provider-form" data-provider-context="${context}"><div class="panel-heading"><div><span class="label">${fromProfile ? 'New profile connection' : 'New provider'}</span><h2 id="provider-dialog-title">${fromProfile ? 'Add a connection to this profile' : 'Add a connection path'}</h2></div><button type="button" class="quiet" data-action="${fromProfile ? 'cancel-provider-profile' : 'cancel-provider'}">← Back</button></div><div class="form-grid"><label>Name<input id="provider-name" name="name" required maxlength="48" placeholder="e.g. Home WireGuard"></label><label>Type<select name="kind" data-provider-kind><option value="custom">Custom VPN</option><option value="warp">Cloudflare WARP</option><option value="proton">Proton VPN</option><option value="wireguard">WireGuard</option><option value="tailscale">Tailscale exit node</option><option value="socks5">SOCKS5 proxy</option></select></label><label class="wide endpoint-field" data-provider-endpoint>Server or endpoint<input name="server" maxlength="120" placeholder="e.g. us-ny-001.example.net"></label><div class="wide provider-fields" data-provider-fields="config"><label>VPN configuration (.conf)<input name="wireguardConfig" type="file" accept=".conf,text/plain"></label><p class="field-note">Choose a WireGuard-compatible file from your computer. This preview validates its endpoint and never stores the private key in browser storage.</p></div><div class="wide provider-fields" data-provider-fields="tailscale" hidden><label>Tailscale exit node<input name="tailscaleExitNode" maxlength="255" placeholder="e.g. my-linux-box or 100.x.y.z"></label><p class="field-note">Use the machine name or Tailscale IP of the Linux box advertising the exit node. Tailscale must be running on both devices.</p></div><div class="wide provider-fields" data-provider-fields="socks5" hidden><div class="form-grid"><label>SOCKS5 host<input name="socksHost" maxlength="255" placeholder="127.0.0.1"></label><label>Port<input name="socksPort" type="number" min="1" max="65535" placeholder="10473"></label></div><p class="field-note">For Windscribe, enter the IP and port shown under Proxy Gateway while Windscribe is connected.</p></div></div><div class="form-actions"><button type="submit" class="primary">${fromProfile ? 'Add connection' : 'Add provider'}</button></div></form>`;
}
function syncProfileDialog(): void {
  const shouldOpen = page === 'Profiles' && editingProfileId !== undefined && !addingProviderFromProfile;
  if (!shouldOpen) {
    if (profileDialog.open) profileDialog.close('sync');
    profileDialog.replaceChildren();
    profileDialog.dataset.context = '';
    return;
  }
  const profile = editingProfileId === 'new' ? undefined : snapshot.profiles.find(item => item.id === editingProfileId);
  const context = editingProfileId === 'new' ? 'new' : `edit:${editingProfileId}`;
  if (!profileDialog.open || profileDialog.dataset.context !== context) {
    if (profileDialog.open) profileDialog.close('replace');
    profileDialog.dataset.context = context;
    profileDialog.returnValue = '';
    profileDialog.innerHTML = profileForm(profile);
    profileDialog.showModal();
    requestAnimationFrame(() => profileDialog.querySelector<HTMLInputElement>('#profile-name')?.focus({ preventScroll: true }));
  }
}
function syncProviderDialog(): void {
  const shouldOpen = addingProvider || addingProviderFromProfile;
  if (!shouldOpen) {
    const returnFocusContext = providerReturnFocusContext;
    providerReturnFocusContext = undefined;
    if (providerDialog.open) providerDialog.close('sync');
    providerDialog.replaceChildren();
    providerDialog.dataset.context = '';
    if (returnFocusContext) {
      requestAnimationFrame(() => app.querySelector<HTMLElement>(`[data-action="${returnFocusContext === 'profile' ? 'new-provider-from-profile' : 'new-provider'}"]`)?.focus({ preventScroll: true }));
    }
    return;
  }
  const context = addingProviderFromProfile ? 'profile' : 'providers';
  if (!providerDialog.open || providerDialog.dataset.context !== context) {
    providerDialog.dataset.context = context;
    providerDialog.returnValue = '';
    providerDialog.innerHTML = providerForm(context);
    if (!providerDialog.open) providerDialog.showModal();
    requestAnimationFrame(() => providerDialog.querySelector<HTMLInputElement>('#provider-name')?.focus({ preventScroll: true }));
  }
}
function providersPage(): string {
  const tailscale = snapshot.settings.tailscale;
  const cards = snapshot.providers.map(provider => `<article class="provider-card provider-managed"><div class="panel-heading"><div><span class="label">${providerKindLabel(provider.kind)}</span><h2>${esc(provider.name)}</h2></div><span class="health-pill ${provider.status}">${provider.status[0].toUpperCase() + provider.status.slice(1)}</span></div><div class="provider-meta"><span>Connection<strong>${esc(provider.server)}</strong></span><span>Latency<strong>${provider.latency ?? '—'} ms</strong></span></div><div class="provider-controls"><label class="sr-only" for="managed-${provider.id}">${esc(provider.name)} server</label><select id="managed-${provider.id}" data-server-provider="${provider.id}">${provider.servers.map(server => `<option ${server === provider.server ? 'selected' : ''}>${esc(server)}</option>`).join('')}</select>${provider.id === activeProfile().providerId ? '<span class="selected-note">Used by active profile</span>' : button('Use in active profile', 'choose-provider', 'quiet', `data-provider="${provider.id}"`)}</div><div class="card-actions">${provider.status === 'offline' ? button('Mark recovered', 'recover-provider', 'quiet', `data-provider="${provider.id}"`) : button('Simulate outage', 'outage-provider', 'quiet danger-text', `data-provider="${provider.id}"`)}</div></article>`).join('');
  return `<section class="page-section"><div class="section-heading"><div><h1 tabindex="-1">Providers</h1><p class="lead">Add WireGuard files, Tailscale exit nodes, or local SOCKS5 gateways here, then choose the connection from Profiles.</p></div><div class="section-actions">${button('Add provider', 'new-provider', 'primary')}</div></div><div class="cards provider-cards provider-management-cards">${cards}</div><article class="panel tailscale-panel"><div class="panel-heading"><div><span class="label">Network coordination</span><h2>Tailscale</h2></div><span class="badge">Profile option</span></div><p class="muted">Add a Tailscale exit node as a provider, then select it in any profile. The live Tailscale client remains responsible for advertising and accepting exit-node routes.</p><label for="tailscale-mode">When a VPN connects<select id="tailscale-mode" data-tailscale-mode><option value="pause-tailscale" ${tailscale.mode === 'pause-tailscale' ? 'selected' : ''}>Pause Tailscale while a VPN is active</option><option value="keep-running" ${tailscale.mode === 'keep-running' ? 'selected' : ''}>Keep Tailscale running</option><option value="prefer-tailscale" ${tailscale.mode === 'prefer-tailscale' ? 'selected' : ''}>Prefer Tailscale when it is active</option></select></label><p class="setting-note"><strong>Current policy:</strong> ${tailscaleModeLabel(tailscale.mode)}</p></article></section>`;
}

function connectivityPage(): string {
  const cards = snapshot.providers.map(provider => `<article class="provider-card ${provider.id === activeProfile().providerId ? 'selected' : ''}"><div class="panel-heading"><div><span class="label">${provider.kind.toUpperCase()}</span><h2>${esc(provider.name)}</h2></div><span class="health-pill ${provider.status}">${provider.status[0].toUpperCase() + provider.status.slice(1)}</span></div><p><strong>${provider.latency ?? '—'} ms</strong> · ${esc(provider.server)}</p><div class="provider-controls"><select aria-label="${esc(provider.name)} server" data-server-provider="${provider.id}">${provider.servers.map(server => `<option ${server === provider.server ? 'selected' : ''}>${esc(server)}</option>`).join('')}</select>${provider.id === activeProfile().providerId ? '<span class="selected-note">In use by active profile</span>' : button('Use provider', 'choose-provider', 'quiet', `data-provider="${provider.id}"`)}</div><div class="card-actions">${provider.status === 'offline' ? button('Mark recovered', 'recover-provider', 'quiet', `data-provider="${provider.id}"`) : button('Simulate outage', 'outage-provider', 'quiet danger-text', `data-provider="${provider.id}"`)}</div></article>`).join('');
  return `<section class="page-section"><div class="section-heading"><div><h1 tabindex="-1">Connectivity</h1><p class="lead">Pick a provider, check its endpoint, and recover quickly when a path goes unhealthy.</p></div><div class="section-actions">${button('Refresh health', 'refresh-health', 'primary')}${button('Reconnect', 'reconnect', 'quiet')}</div></div><div class="cards provider-cards">${cards}</div><article class="panel info-row"><span class="status-dot" aria-hidden="true"></span><div><strong>Automatic recovery is ${snapshot.settings.autoSwitch ? 'on' : 'off'}.</strong><p class="muted">The router can try another provider after ${snapshot.settings.switchAfterErrors} TLS errors.</p></div><a class="text-link" href="#settings">Tune recovery <span aria-hidden="true">↗</span></a></article></section>`;
}

function toggle(name: string, label: string, checked: boolean, note: string): string { return `<label class="setting-row"><span><strong>${label}</strong><small>${note}</small></span><input type="checkbox" data-setting="${name}" ${checked ? 'checked' : ''}></label>`; }
function settingsPage(): string {
  return `<section class="page-section"><div class="section-heading"><div><h1 tabindex="-1">Settings</h1><p class="lead">Small defaults that make the local proxy feel like a normal VPN client.</p></div><span class="badge">Saved locally</span></div><div class="two-column"><article class="panel settings-panel"><h2>Window & connection</h2>${toggle('launchAtLogin', 'Launch at login', snapshot.settings.launchAtLogin, 'Start the tray helper when you sign in.')}${toggle('closeToTray', 'Close to tray', snapshot.settings.closeToTray, 'Closing the window hides it; the tray menu can reopen it.')}${toggle('disconnectOnNetworkLoss', 'Disconnect on Wi-Fi loss', snapshot.settings.disconnectOnNetworkLoss, 'Prevent stale routes while moving between networks.')}${toggle('autoSwitch', 'Auto-switch providers', snapshot.settings.autoSwitch, 'Try the healthiest provider after repeated TLS errors.')}${toggle('fullTunnel', 'Full tunnel mode', snapshot.settings.fullTunnel, 'Route all traffic instead of only selected domains.')}</article><article class="panel settings-panel"><h2>Router details</h2><label>Proxy port<input type="number" min="1024" max="65535" data-setting-number="proxyPort" value="${snapshot.settings.proxyPort}"></label><label>Switch after TLS errors<select data-setting-select="switchAfterErrors"><option value="3" ${snapshot.settings.switchAfterErrors === 3 ? 'selected' : ''}>3 errors</option><option value="5" ${snapshot.settings.switchAfterErrors === 5 ? 'selected' : ''}>5 errors</option><option value="8" ${snapshot.settings.switchAfterErrors === 8 ? 'selected' : ''}>8 errors</option></select></label><label>Log detail<select data-setting-select="logLevel"><option value="normal" ${snapshot.settings.logLevel === 'normal' ? 'selected' : ''}>Normal</option><option value="verbose" ${snapshot.settings.logLevel === 'verbose' ? 'selected' : ''}>Verbose</option></select></label><div class="setting-link"><a class="text-link" href="#appearance">Customize appearance <span aria-hidden="true">↗</span></a></div></article></div></section>`;
}

function appearancePage(): string {
  const layoutPresets = (['vertical', 'horizontal'] as LayoutPreset[]).map(item => {
    const selected = snapshot.theme.layout === item;
    const name = item === 'vertical' ? 'Vertical' : 'Horizontal';
    const note = item === 'vertical' ? 'Stacked controls for a narrow window.' : 'Side-by-side controls for a wide window.';
    return `<button type='button' class='layout-preset ${selected ? 'selected' : ''}' data-action='theme-layout' data-layout='${item}' aria-pressed='${selected}'><strong>${name}</strong><small>${note}</small></button>`;
  }).join('');
  const schemeOptions = (['system', 'light', 'dark'] as Scheme[]).map(item => `<option value='${item}' ${snapshot.theme.scheme === item ? 'selected' : ''}>${item[0].toUpperCase() + item.slice(1)}</option>`).join('');
  const accentOptions = accents.map(item => `<option value='${item.id}' ${snapshot.theme.accent === item.id ? 'selected' : ''}>${item.name}</option>`).join('');
  return `<section class='page-section'><div class='section-heading'><div><h1 tabindex='-1'>Appearance</h1><p class='lead'>Choose a layout preset, then tune colour, density, and motion.</p></div><span class='badge'>Live preview</span></div><article class='panel'><div class='panel-heading'><div><span class='label'>Layout preset</span><h2>Choose how content is arranged</h2></div></div><div class='layout-presets' role='group' aria-label='Layout preset'>${layoutPresets}</div></article><article class='panel'><div class='panel-heading'><div><span class='label'>Theme</span><h2>Colour and scheme</h2></div></div><div class='two-column appearance-fields'><label>Colour scheme<select data-theme-scheme>${schemeOptions}</select></label><label>Accent<select data-theme-accent>${accentOptions}</select></label></div></article><div class='two-column'><article class='panel compact-controls'><h2>Details</h2><label>Density<select data-theme-density><option value='compact' ${snapshot.theme.density === 'compact' ? 'selected' : ''}>Compact</option><option value='comfortable' ${snapshot.theme.density === 'comfortable' ? 'selected' : ''}>Comfortable</option></select></label><label>Contrast<select data-theme-contrast><option value='standard' ${snapshot.theme.contrast === 'standard' ? 'selected' : ''}>Standard</option><option value='high' ${snapshot.theme.contrast === 'high' ? 'selected' : ''}>High</option></select></label><label>Animation speed<select id='animation-speed' data-theme-speed><option value='fast' ${snapshot.theme.motionSpeed === 'fast' ? 'selected' : ''}>Fast</option><option value='normal' ${snapshot.theme.motionSpeed === 'normal' ? 'selected' : ''}>Normal</option><option value='slow' ${snapshot.theme.motionSpeed === 'slow' ? 'selected' : ''}>Slow</option></select></label><label class='setting-row'><span><strong>Reduce motion</strong><small>Respect a calmer interaction style.</small></span><input type='checkbox' data-theme-motion ${snapshot.theme.reducedMotion ? 'checked' : ''}></label></article><article class='panel preview-card'><span class='label'>Preview</span><div class='mini-window'><span class='mini-dot'></span><strong>${esc(activeProfile().name)}</strong><span class='mini-line'></span><button type='button' class='mini-button'>Connected</button></div><p class='muted'>The selected style applies immediately and persists across launches.</p></article></div></section>`;
}

function aboutPage(): string {
  const logs = snapshot.logs.slice(0, 8).map(log => `<li><span class="log-dot"></span><span>${esc(log)}</span><time>now</time></li>`).join('');
  return `<section class="page-section"><div class="section-heading"><div><h1 tabindex="-1">About</h1><p class="lead">A small native shell around the existing Python router. The dashboard is local-first and ready for the live controller contract.</p></div><span class="badge">v0.1 dashboard</span></div><article class="panel"><div class="panel-heading"><div><span class="label">Diagnostics</span><h2>Recent events</h2></div><button type="button" class="quiet" data-action="export-logs">Export</button></div><ul class="logs">${logs}</ul></article><article class="panel danger-zone"><div><h2>Reset local prototype</h2><p class="muted">Remove saved profiles, themes, and settings from this browser only.</p></div>${button('Reset demo data', 'reset-data', 'quiet danger-text')}</article></section>`;
}

function render(): void {
  app.dataset.state = previewState;
  app.dataset.page = page.toLowerCase();
  if (!isTauri() && lastTrayState !== previewState) { lastTrayState = previewState; setTrayStatus(previewState); }
  document.querySelector('#page-label')!.textContent = page; document.title = `${page} — Proxy router`;
  document.querySelector('#rail-status')!.textContent = busy ? 'Saving…' : previewState === 'failed' ? 'Controller unavailable' : `${snapshot.connection[0].toUpperCase()}${snapshot.connection.slice(1)}`;
  const nav = document.querySelector<HTMLElement>('#nav')!;
  nav.innerHTML = pages.map(item => {
    const current = item === page;
    return `<a href="#${item.toLowerCase()}" class="${current ? 'current' : ''}"${current ? ' aria-current="page"' : ''}>${item}</a>`;
  }).join('');
  main.innerHTML = page === 'Home' ? homePage() : page === 'Profiles' ? profilesPage() : page === 'Providers' ? providersPage() : page === 'Connectivity' ? connectivityPage() : page === 'Settings' ? settingsPage() : page === 'Appearance' ? appearancePage() : aboutPage();
  syncProfileDialog();
  syncProviderDialog();
  applyTheme();
}

function resetMainScroll(): void {
  main.scrollTo({ top: 0, left: 0, behavior: 'auto' });
}

async function refreshStatus(options?: { silent?: boolean }): Promise<void> {
  const generation = ++requestGeneration;
  if (!options?.silent) { previewState = 'loading'; render(); }
  try { status = await getPreviewStatus(); if (generation !== requestGeneration) return; }
  catch { if (generation !== requestGeneration) return; if (!options?.silent) { previewState = 'failed'; } }
  // In the desktop app the hero and the tray follow the real controller, not
  // the build-time fixture; an unreadable controller is a real failure (#144).
  if (isTauri()) {
    try {
      const live = await getLiveStatus();
      if (generation !== requestGeneration) return;
      previewState = (states as readonly string[]).includes(live.state) ? live.state : 'failed';
    } catch {
      if (generation !== requestGeneration) return;
      previewState = 'failed';
    }
  }
  render(); announce(copy[previewState][0]);
}
function navigate(focus: boolean): void { const name = location.hash.slice(1).toLowerCase(); if (name === 'routing') { history.replaceState(null, '', '#profiles'); page = 'Profiles'; } else page = pages.find(item => item.toLowerCase() === name) ?? 'Home'; menu.setAttribute('aria-expanded', 'false'); render(); resetMainScroll(); if (focus) main.querySelector<HTMLElement>('h1')?.focus({ preventScroll: true }); }
function formInput(form: HTMLFormElement, name: string): string { return (new FormData(form).get(name) as string | null ?? '').trim(); }
function readProfileDraft(form: HTMLFormElement): Omit<Profile, 'id' | 'updatedAt'> {
  return { name: formInput(form, 'name'), description: formInput(form, 'description'), providerId: formInput(form, 'providerId'), routeMode: formInput(form, 'routeMode') as RouteMode, domains: (formInput(form, 'domains') || '').split('\n'), autoSubdomains: form.querySelector<HTMLInputElement>('[name="autoSubdomains"]')?.checked ?? false, fallback: formInput(form, 'fallback') as FallbackMode };
}
function download(filename: string, content: string, type = 'application/json'): void { const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([content], { type })); link.download = filename; document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(link.href); }

menu.addEventListener('click', () => menu.setAttribute('aria-expanded', String(menu.getAttribute('aria-expanded') !== 'true')));
document.querySelector('#preview')!.addEventListener('click', () => { scenario.value = previewState; previewDialog.showModal(); });
providerDialog.addEventListener('cancel', event => {
  if (!addingProvider && !addingProviderFromProfile) return;
  event.preventDefault();
  addingProvider = false;
  addingProviderFromProfile = false;
  render();
});
providerDialog.addEventListener('close', () => {
  providerDialog.returnValue = '';
});
profileDialog.addEventListener('cancel', event => {
  if (editingProfileId === undefined) return;
  event.preventDefault();
  editingProfileId = undefined;
  pendingProviderId = undefined;
  profileDraft = undefined;
  addingProviderFromProfile = false;
  render();
});
profileDialog.addEventListener('close', () => {
  profileDialog.returnValue = '';
});
previewDialog.addEventListener('close', () => { if (previewDialog.returnValue === 'apply') { ++requestGeneration; previewState = scenario.value as PreviewState; page = 'Home'; history.replaceState(null, '', '#home'); render(); resetMainScroll(); announce(copy[previewState][0]); if (previewState === 'loading') window.setTimeout(() => { if (previewState === 'loading') { previewState = 'failed'; render(); announce(copy.failed[0]); } }, 3000); } previewDialog.returnValue = ''; document.querySelector<HTMLButtonElement>('#preview')?.focus({ preventScroll: true }); });
importDialog.addEventListener('close', () => { if (importDialog.returnValue === 'import') { const raw = document.querySelector<HTMLTextAreaElement>('#profile-json')!.value; void perform(() => controller.importProfile(raw)); } importDialog.returnValue = ''; });
document.querySelector('#import-form')!.addEventListener('submit', event => { if ((event as SubmitEvent).submitter && ((event as SubmitEvent).submitter as HTMLButtonElement).value !== 'import') return; event.preventDefault(); importDialog.close('import'); });

app.addEventListener('click', event => {
  const element = event.target as HTMLElement;
  const trigger = profileMenuTriggerFor(element);
  if (trigger) { const isOpen = trigger.getAttribute('aria-expanded') === 'true'; closeProfileMenus(trigger); profileMenu(trigger, !isOpen); return; }
  const option = element.closest<HTMLElement>('[data-profile-option]');
  if (option?.dataset.profileOption) {
    const owningTrigger = option.closest<HTMLElement>('[data-profile-picker]')?.querySelector<HTMLElement>('[data-profile-trigger]');
    if (owningTrigger) profileMenu(owningTrigger, false);
    void selectProfile(option.dataset.profileOption!);
    return;
  }
  closeProfileMenus();
  const target = element.closest<HTMLElement>('[data-action]'); if (!target) return;
  const action = target.dataset.action; const profileId = target.dataset.profile;
  if (action === 'connect' || action === 'disconnect' || action === 'reconnect') {
    // Desktop: change the real engine, then re-read it so the hero shows the
    // truth. Browser preview keeps the local demo controller.
    void (async () => {
      if (isTauri()) {
        try { await applyEngineAction(action); } catch (error) { announce(error instanceof Error ? error.message : 'Engine action failed'); }
        await refreshStatus();
        render();
        return;
      }
      await perform(() => action === 'connect' ? controller.connect() : action === 'disconnect' ? controller.disconnect() : controller.reconnect());
    })();
  }
  else if (action === 'refresh') void refreshStatus();
  else if (action === 'new-profile') { editingProfileId = 'new'; pendingProviderId = undefined; profileDraft = undefined; addingProviderFromProfile = false; render(); }
  else if (action === 'cancel-profile') { editingProfileId = undefined; pendingProviderId = undefined; profileDraft = undefined; addingProviderFromProfile = false; render(); }
  else if (action === 'new-provider') { providerReturnFocusContext = 'providers'; addingProvider = true; render(); }
  else if (action === 'cancel-provider') { addingProvider = false; render(); }
  else if (action === 'new-provider-from-profile') { providerReturnFocusContext = 'profile'; const form = app.querySelector<HTMLFormElement>('#profile-form'); if (form) profileDraft = readProfileDraft(form); addingProviderFromProfile = true; render(); }
  else if (action === 'cancel-provider-profile') { addingProviderFromProfile = false; render(); }
  else if (action === 'edit-profile' && profileId) { editingProfileId = profileId; render(); }
  else if (action === 'select-profile' && profileId) void selectProfile(profileId);
  else if (action === 'duplicate-profile' && profileId) void perform(() => controller.duplicateProfile(profileId));
  else if (action === 'delete-profile' && profileId) void perform(() => controller.deleteProfile(profileId));
  else if (action === 'export-profile' && profileId) { download(`${profileId}.proxy-router.json`, controller.exportProfile(profileId)); announce('Profile export ready'); }
  else if (action === 'import-profile') { document.querySelector<HTMLTextAreaElement>('#profile-json')!.value = ''; importDialog.showModal(); }
  else if (action === 'choose-provider' && target.dataset.provider) void perform(() => controller.setProvider(target.dataset.provider!));
  else if (action === 'refresh-health') void perform(() => controller.refreshHealth());
  else if (action === 'theme-layout' && target.dataset.layout) void perform(() => controller.updateTheme({ layout: target.dataset.layout as LayoutPreset }));
  else if (action === 'theme-scheme' && target.dataset.scheme) void perform(() => controller.updateTheme({ scheme: target.dataset.scheme as Scheme }));
  else if (action === 'theme-accent' && target.dataset.accent) void perform(() => controller.updateTheme({ accent: target.dataset.accent as Accent }));
  else if (action === 'export-logs') { download('proxy-router-logs.json', JSON.stringify({ exportedAt: new Date().toISOString(), logs: snapshot.logs }, null, 2)); announce('Log export ready'); }
  else if (action === 'reset-data' && window.confirm('Reset local dashboard data?')) { snapshot = controller.reset(); previewState = snapshot.connection; render(); announce('Demo data reset'); }
});
app.addEventListener('keydown', event => {
  const element = event.target as HTMLElement;
  const trigger = profileMenuTriggerFor(element) ?? element.closest<HTMLElement>('[data-profile-picker]')?.querySelector<HTMLElement>('[data-profile-trigger]');
  if (!trigger) return;
  const menuId = trigger.getAttribute('aria-controls');
  const menu = menuId ? document.getElementById(menuId) : null;
  const isOpen = trigger.getAttribute('aria-expanded') === 'true';
  if (element.matches('[data-profile-option]') && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault();
    const profileId = element.dataset.profileOption;
    if (profileId) { profileMenu(trigger, false); void selectProfile(profileId); }
  } else if (event.key === 'Escape') {
    event.preventDefault(); profileMenu(trigger, false); trigger.focus();
  } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    if (!isOpen) profileMenu(trigger, true, true); else moveProfileOption(trigger, event.key === 'ArrowDown' ? 1 : -1);
  } else if (isOpen && (event.key === 'Home' || event.key === 'End') && menu) {
    event.preventDefault();
    const option = event.key === 'Home' ? menu.firstElementChild : menu.lastElementChild;
    (option as HTMLElement | null)?.focus();
  }
});
document.addEventListener('click', event => {
  if (!(event.target instanceof Node) || !app.contains(event.target)) closeProfileMenus();
});
app.addEventListener('change', event => {
  const target = event.target as HTMLInputElement | HTMLSelectElement; if (target.dataset.bind === 'active-profile') void perform(() => controller.selectProfile(target.value));
  else if (target.dataset.bind === 'fallback') void perform(() => controller.setFallback(target.value as FallbackMode));
  else if (target.hasAttribute('data-provider-kind')) {
    const kind = target.value;
    const endpoint = app.querySelector<HTMLElement>('[data-provider-endpoint]');
    const wireguard = app.querySelector<HTMLElement>('[data-provider-fields="config"]');
    const tailscale = app.querySelector<HTMLElement>('[data-provider-fields="tailscale"]');
    const socks5 = app.querySelector<HTMLElement>('[data-provider-fields="socks5"]');
    if (endpoint) endpoint.hidden = kind === 'wireguard' || kind === 'socks5' || kind === 'tailscale';
    if (wireguard) wireguard.hidden = kind !== 'wireguard' && kind !== 'custom';
    if (tailscale) tailscale.hidden = kind !== 'tailscale';
    if (socks5) socks5.hidden = kind !== 'socks5';
    const file = app.querySelector<HTMLInputElement>('[name="wireguardConfig"]');
    if (file) file.required = kind === 'wireguard';
    const exitNode = app.querySelector<HTMLInputElement>('[name="tailscaleExitNode"]');
    if (exitNode) exitNode.required = kind === 'tailscale';
  }
  else if (target.dataset.serverProvider) void perform(() => controller.setServer(target.dataset.serverProvider!, target.value));
  else if (target.hasAttribute('data-theme-scheme')) void perform(() => controller.updateTheme({ scheme: target.value as Scheme }));
  else if (target.hasAttribute('data-theme-accent')) void perform(() => controller.updateTheme({ accent: target.value as Accent }));
  else if (target.hasAttribute('data-theme-motion')) void perform(() => controller.updateTheme({ reducedMotion: (target as HTMLInputElement).checked }));
  else if (target.hasAttribute('data-theme-speed')) void perform(() => controller.updateTheme({ motionSpeed: target.value as MotionSpeed }));
  else if (target.hasAttribute('data-tailscale-mode')) void perform(() => controller.updateTailscale({ mode: target.value as TailscaleMode }));
  else if (target.dataset.setting) { const key = target.dataset.setting as 'launchAtLogin' | 'closeToTray' | 'disconnectOnNetworkLoss' | 'autoSwitch' | 'fullTunnel'; void perform(() => controller.updateSettings({ [key]: (target as HTMLInputElement).checked })); }
  else if (target.dataset.settingNumber) { const key = target.dataset.settingNumber as 'proxyPort'; void perform(() => controller.updateSettings({ [key]: Number(target.value) })); }
  else if (target.dataset.settingSelect) { const key = target.dataset.settingSelect as 'switchAfterErrors' | 'logLevel'; const value = key === 'logLevel' ? target.value as 'normal' | 'verbose' : Number(target.value); void perform(() => controller.updateSettings({ [key]: value } as Partial<Snapshot['settings']>)); }
  else if (target.hasAttribute('data-theme-density')) void perform(() => controller.updateTheme({ density: target.value as Density }));
  else if (target.hasAttribute('data-theme-contrast')) void perform(() => controller.updateTheme({ contrast: target.value as 'standard' | 'high' }));
});
app.addEventListener('input', event => {
  const target = event.target as HTMLInputElement;
  if (target.hasAttribute('data-setting-number') && Number.isFinite(Number(target.value))) {
    const key = target.dataset.settingNumber as 'proxyPort'; void perform(() => controller.updateSettings({ [key]: Number(target.value) }));
  }
});
app.addEventListener('submit', event => {
  const form = event.target as HTMLFormElement; if (form.id === 'domain-form') { event.preventDefault(); const domain = formInput(form, 'domain'); void perform(() => controller.addDomain(domain)); }
  if (form.id === 'provider-form') {
    event.preventDefault();
    const name = formInput(form, 'name'); const kind = formInput(form, 'kind') as ProviderKind; const context = form.dataset.providerContext === 'profile' ? 'profile' : 'providers';
    void perform(async () => {
      let next: Snapshot;
      const file = new FormData(form).get('wireguardConfig');
      if (kind === 'wireguard' || (kind === 'custom' && file instanceof File && file.size > 0)) {
        if (!(file instanceof File) || file.size === 0) throw new Error('Choose a VPN .conf file');
        next = await controller.importProviderConfig({ name, kind, fileName: file.name, raw: await file.text() });
      } else if (kind === 'tailscale') {
        next = await controller.addTailscaleProvider({ name, exitNode: formInput(form, 'tailscaleExitNode') });
      } else if (kind === 'socks5') {
        next = await controller.addSocks5Provider({ name, host: formInput(form, 'socksHost'), port: formInput(form, 'socksPort') });
      } else {
        next = await controller.addProvider({ name, kind, server: formInput(form, 'server') });
      }
      if (context === 'profile') { pendingProviderId = next.providers[next.providers.length - 1]?.id; addingProviderFromProfile = false; }
      else addingProvider = false;
      return next;
    });
  }
  if (form.id === 'profile-form') { event.preventDefault(); const data = readProfileDraft(form); const current = editingProfileId; void perform(async () => { const next = await controller.saveProfile(data, current === 'new' ? undefined : current); editingProfileId = undefined; pendingProviderId = undefined; profileDraft = undefined; return next; }); }
});
async function selectProfile(profileId: string): Promise<void> {
  if (isTauri()) {
    try { await applyProfileToEngine(profileId); } catch (error) { announce(error instanceof Error ? error.message : 'Profile switch failed'); }
  }
  await perform(() => controller.selectProfile(profileId));
  if (isTauri()) { await refreshStatus(); render(); }
}

window.addEventListener('hashchange', () => navigate(true));
navigate(false); requestAnimationFrame(reportPreviewFrame);

// The hero, the rail and the tray follow the real controller (#144):
// refresh now and poll on the cadence the Rust backend already uses.
if (isTauri()) {
  void refreshStatus({ silent: true });
  window.setInterval(() => { if (!busy) void refreshStatus({ silent: true }); }, 5000);
}
