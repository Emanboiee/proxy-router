import type {EngineConfig, Snapshot} from './controller';
import './dashboard-polish.css';

interface DashboardPresentation {
  page: string;
  desktop: boolean;
  snapshot: Snapshot;
  config: EngineConfig | null;
  configUnavailable: boolean;
  status: Record<string, unknown> | null;
}

const classes = ['polished-preview', 'profiles-v2', 'overview-v3', 'dashboard-v4', 'dashboard-v5', 'dashboard-v6', 'dashboard-v7', 'dashboard-v8', 'production-dashboard'];
const paths: Record<string, string> = {
  home: 'M3 10 12 3l9 7v11h-6v-7H9v7H3Z',
  profiles: 'M4 5h16M4 12h12M4 19h16',
  providers: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M3 12h18M12 3c-5 5-5 13 0 18M12 3c5 5 5 13 0 18',
  connectivity: 'M3 8a15 15 0 0 1 18 0M6 12a10 10 0 0 1 12 0M9 16a5 5 0 0 1 6 0M12 20h.01',
  settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2',
  appearance: 'M12 3a9 9 0 1 0 0 18h2a2 2 0 0 0 0-4h-1a2 2 0 0 1 0-4h4a4 4 0 0 0 4-4c0-4-4-6-9-6M7 9h.01M11 6h.01M16 7h.01',
};
let profileQuery = '';
let providerQuery = '';
let selectedProvider = '';

function storageGet(key: string): string | null {
  try { return localStorage.getItem(key); } catch { return null; }
}
function storageSet(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* Appearance remains usable when storage is unavailable. */ }
}

interface CustomTheme {name: string; color: string}
function savedThemes(): CustomTheme[] {
  try {
    const value: unknown = JSON.parse(storageGet('router-custom-themes') ?? '[]');
    if (!Array.isArray(value)) return [];
    return value.filter((theme): theme is CustomTheme => theme !== null && typeof theme === 'object' && typeof theme.name === 'string' && theme.name.length <= 40 && typeof theme.color === 'string' && /^#[\da-f]{6}$/i.test(theme.color)).slice(0, 12);
  } catch { return []; }
}

function colorHue(color: string): number {
  const [r, g, b] = [1, 3, 5].map(offset => parseInt(color.slice(offset, offset + 2), 16) / 255);
  const max = Math.max(r, g, b), delta = max - Math.min(r, g, b);
  if (!delta) return 230;
  let value = (r - g) / delta + 4;
  if (max === r) value = (g - b) / delta;
  else if (max === g) value = (b - r) / delta + 2;
  return (value * 60 + 360) % 360;
}

export function applyDashboardPalette(): void {
  const root = document.documentElement;
  const light = root.dataset.scheme === 'light' || root.dataset.scheme === 'system' && matchMedia('(prefers-color-scheme: light)').matches;
  const hues: Record<string, number> = {signal: 230, ocean: 205, moss: 145, iris: 265};
  const custom = storageGet('router-custom-theme-color');
  const hue = custom && /^#[\da-f]{6}$/i.test(custom) ? colorHue(custom) : hues[root.dataset.accent ?? 'signal'] ?? 230;
  const high = root.dataset.contrast === 'high';
  const palette: Record<string, string> = light ? {
    canvas: `hsl(${hue} 25% 96%)`, surface: `hsl(${hue} 30% 99%)`, raised: `hsl(${hue} 24% 93%)`, 'raised-2': `hsl(${hue} 25% 88%)`,
    ink: `hsl(${hue} 28% 14%)`, muted: `hsl(${hue} 16% 37%)`, line: `hsl(${hue} 22% ${high ? 56 : 80}%)`, 'line-strong': `hsl(${hue} 20% 52%)`,
    accent: `hsl(${hue} 60% 42%)`, focus: `hsl(${hue} 65% 38%)`, 'accent-ink': '#ffffff', success: '#22663b', warning: '#805400',
  } : {
    canvas: `hsl(${hue} 24% 11%)`, surface: `hsl(${hue} 23% 14%)`, raised: `hsl(${hue} 22% 19%)`, 'raised-2': `hsl(${hue} 24% 24%)`,
    ink: `hsl(${hue} 30% 94%)`, muted: `hsl(${hue} 16% 72%)`, line: `hsl(${hue} 20% ${high ? 48 : 29}%)`, 'line-strong': `hsl(${hue} 22% 48%)`,
    accent: `hsl(${hue} 65% 76%)`, focus: `hsl(${hue} 80% 84%)`, 'accent-ink': '#131521', success: '#87d9a3', warning: '#efc276',
  };
  Object.entries(palette).forEach(([name, value]) => root.style.setProperty(`--${name}`, value));
}

function icon(name: string): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('aria-hidden', 'true'); svg.classList.add('nav-icon');
  const path = document.createElementNS(svg.namespaceURI, 'path'); path.setAttribute('d', paths[name] ?? paths.providers); svg.append(path);
  return svg;
}

function polishEditors(): void {
  document.querySelectorAll<HTMLFormElement>('.editor').forEach(form => {
    if (form.dataset.compact) return;
    form.dataset.compact = 'true';
    const cancel = form.querySelector<HTMLButtonElement>('.panel-heading button');
    const footer = form.querySelector('.form-actions');
    if (cancel && footer) {
      const close = cancel.cloneNode(true) as HTMLButtonElement;
      close.textContent = '×'; close.className = 'dialog-close'; close.setAttribute('aria-label', 'Close editor');
      cancel.before(close); cancel.textContent = 'Cancel'; footer.prepend(cancel);
    }
    const advanced = form.querySelector('[data-action="profile-enable-rules"]');
    if (advanced) {
      const details = document.createElement('details'); details.className = 'editor-advanced';
      const summary = document.createElement('summary'); summary.textContent = 'Advanced routing';
      advanced.before(details); details.append(summary, advanced);
    }
    const source = form.querySelector<HTMLSelectElement>('select[name="kind"]');
    const file = form.querySelector<HTMLInputElement>('input[name="wireguardConfig"]');
    if (file) {
      const importer = document.createElement('div'); importer.className = 'config-import-control';
      const choose = document.createElement('button'); choose.type = 'button'; choose.className = 'quiet'; choose.textContent = 'Choose .conf files';
      const selected = document.createElement('span'); selected.className = 'field-note'; selected.setAttribute('role', 'status');
      selected.textContent = 'No files selected'; file.hidden = true;
      choose.addEventListener('click', () => file.click());
      file.addEventListener('change', () => {selected.textContent = [...(file.files ?? [])].map(item => item.name).join(', ') || 'No files selected';});
      file.after(importer); importer.append(choose, selected);
    }
    if (!source) return;
    const editingWireGuard = /^Edit |^Add server to /.test(form.querySelector('h2')?.textContent ?? '') && ['wireguard', 'proton', 'custom'].includes(source.value);
    if (source.disabled || editingWireGuard) {
      source.closest('label')?.classList.add('provider-type-source');
      const protocol = document.createElement('p'); protocol.className = 'field-note';
      protocol.textContent = 'WireGuard server pool · Import configs into this provider below.';
      form.querySelector('.form-grid')?.before(protocol);
      return;
    }
    const group = document.createElement('fieldset'); group.className = 'connection-choices';
    const legend = document.createElement('legend'); legend.textContent = 'Connection type'; group.append(legend);
    [...source.options].forEach(option => {
      const button = document.createElement('button'); button.type = 'button'; button.textContent = option.text;
      button.setAttribute('aria-pressed', String(source.value === option.value));
      button.addEventListener('click', () => {
        source.value = option.value;
        group.querySelectorAll('button').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
        source.dispatchEvent(new Event('change', {bubbles: true}));
      });
      group.append(button);
    });
    source.closest('label')?.classList.add('provider-type-source');
    form.querySelector('.form-grid')?.before(group);
  });
}

function addSearch(list: HTMLElement, kind: 'profile' | 'provider', filter: (query: string) => void): void {
  if (list.parentElement?.querySelector(`.${kind}-toolbar`)) return;
  const toolbar = document.createElement('label'); toolbar.className = `${kind}-toolbar`;
  toolbar.textContent = kind === 'profile' ? 'Find a profile' : 'Find a connection';
  const input = document.createElement('input'); input.type = 'search'; input.id = `${kind}-search`;
  input.placeholder = kind === 'profile' ? 'Search name, provider, or domains' : 'Search provider or endpoint';
  input.value = kind === 'profile' ? profileQuery : providerQuery;
  const empty = document.createElement('p'); empty.className = 'search-empty'; empty.hidden = true; empty.setAttribute('role', 'status');
  empty.textContent = 'No matches. Try another search.';
  toolbar.append(input); list.before(toolbar); list.after(empty);
  const update = (): void => {
    if (kind === 'profile') profileQuery = input.value; else providerQuery = input.value;
    filter(input.value.toLowerCase());
    const rows = list.querySelectorAll<HTMLElement>(kind === 'profile' ? '.profile-card' : '.provider-instances button');
    empty.hidden = !rows.length || [...rows].some(row => !row.hidden);
  };
  input.addEventListener('input', update); update();
}

function polishProfiles(): void {
  const list = document.querySelector<HTMLElement>('.profile-cards'); if (!list) return;
  list.closest('section')?.querySelector('.tip')?.remove();
  list.querySelectorAll<HTMLElement>('.profile-card').forEach(row => {
    if (row.dataset.polished) return;
    row.dataset.polished = 'true';
    const actions = row.querySelector('.card-actions'); if (!actions) return;
    const secondary = [...actions.querySelectorAll<HTMLButtonElement>('button')].filter(button => ['duplicate-profile', 'export-profile', 'delete-profile'].includes(button.dataset.action ?? ''));
    if (!secondary.length) return;
    const more = document.createElement('details'); more.className = 'profile-more';
    const summary = document.createElement('summary'); summary.textContent = 'More'; summary.setAttribute('aria-label', `More actions for ${row.querySelector('h2')?.textContent ?? 'profile'}`);
    const contents = document.createElement('div'); contents.className = 'profile-more-actions'; more.append(summary, contents);
    secondary.forEach(button => contents.append(button)); actions.append(more);
  });
  addSearch(list, 'profile', query => list.querySelectorAll<HTMLElement>('.profile-card').forEach(row => {row.hidden = !row.textContent?.toLowerCase().includes(query);}));
}

function polishProviders(desktop: boolean, providers: Snapshot['providers']): void {
  const list = document.querySelector<HTMLElement>('.provider-management-cards');
  if (!list || list.querySelector('.provider-studio')) return;
  const cards = [...list.querySelectorAll<HTMLElement>('.provider-card')]; if (!cards.length) return;
  cards.forEach((card, index) => {
    const actions = card.querySelector<HTMLElement>('.card-actions');
    if (!actions) return;
    if (!desktop) {
      const provider = providers[index];
      if (provider) {
        const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'quiet';
        edit.textContent = 'Edit provider'; edit.dataset.action = 'edit-provider'; edit.dataset.provider = provider.id;
        actions.prepend(edit);
        if (['proton', 'wireguard', 'custom'].includes(provider.kind) || provider.connection?.kind === 'wireguard') {
          const add = document.createElement('button'); add.type = 'button'; add.className = 'primary';
          add.textContent = 'Add WireGuard configs'; add.dataset.action = 'add-provider-server'; add.dataset.provider = provider.id;
          edit.after(add);
        }
      }
    }
    card.querySelector('.panel-heading')?.after(actions);
  });
  const studio = document.createElement('div'); studio.className = 'provider-studio';
  const nav = document.createElement('div'); nav.className = 'provider-instances'; nav.setAttribute('role', 'group'); nav.setAttribute('aria-label', 'Providers');
  const detail = document.createElement('div'); detail.className = 'provider-detail';
  const ids = cards.map((card, index) => card.querySelector<HTMLElement>('[data-provider]')?.dataset.provider ?? String(index));
  if (!ids.includes(selectedProvider)) selectedProvider = ids[0];
  const buttons: HTMLButtonElement[] = [];
  function select(index: number): void {
    selectedProvider = ids[index];
    cards.forEach((card, i) => card.classList.toggle('provider-inactive', i !== index));
    buttons.forEach((button, i) => button.setAttribute('aria-pressed', String(i === index)));
  }
  cards.forEach(card => {
    const button = document.createElement('button'); button.type = 'button';
    const name = document.createElement('strong'); name.textContent = card.querySelector('h2')?.textContent ?? 'Provider';
    const label = document.createElement('span'); label.textContent = desktop ? 'Saved connection' : `${card.querySelector('.health-pill')?.textContent ?? 'Sample'} · sample`;
    button.append(icon('providers'), name, label); buttons.push(button); nav.append(button); detail.append(card);
    button.addEventListener('click', () => select(buttons.indexOf(button)));
  });
  select(ids.indexOf(selectedProvider)); studio.append(nav, detail); list.append(studio);
  addSearch(list, 'provider', query => {
    buttons.forEach((button, index) => {button.hidden = !cards[index].textContent?.toLowerCase().includes(query);});
    const visible = buttons.findIndex(button => !button.hidden);
    if (visible >= 0 && buttons[ids.indexOf(selectedProvider)]?.hidden) select(visible);
    detail.hidden = visible < 0;
  });
}

function visualChoices(source: HTMLSelectElement, kind: 'schemes' | 'themes'): HTMLElement {
  const group = document.createElement('div'); group.className = `visual-choices ${kind}`;
  group.setAttribute('role', 'group'); group.setAttribute('aria-label', kind === 'schemes' ? 'Color scheme' : 'Theme');
  [...source.options].forEach(option => {
    const button = document.createElement('button'); button.type = 'button'; button.dataset.choice = option.value;
    button.setAttribute('aria-pressed', String(source.value === option.value && (kind !== 'themes' || !storageGet('router-custom-theme-color'))));
    button.innerHTML = kind === 'schemes' ? '<span class="scheme-window" aria-hidden="true"><i></i><span><b></b><b></b><b></b></span></span>' : '<span class="theme-orbs" aria-hidden="true"><i></i><i></i></span>';
    const name = document.createElement('strong'); name.textContent = option.text; button.append(name);
    button.addEventListener('click', () => {if (kind === 'themes') storageSet('router-custom-theme-color', ''); source.value = option.value; source.dispatchEvent(new Event('change', {bubbles: true}));});
    group.append(button);
  });
  return group;
}

function polishAppearance(): void {
  const section = document.querySelector<HTMLElement>('#main .page-section'); if (!section || section.dataset.studio) return;
  section.dataset.studio = 'true';
  const scheme = section.querySelector<HTMLSelectElement>('[data-theme-scheme]');
  const accent = section.querySelector<HTMLSelectElement>('[data-theme-accent]'); if (!scheme || !accent) return;
  scheme.setAttribute('aria-label', 'Colour scheme'); accent.setAttribute('aria-label', 'Accent');
  const controls = [...section.querySelectorAll<HTMLSelectElement>('select')].filter(source => source !== scheme && source !== accent);
  const motion = section.querySelector('[data-theme-motion]')?.closest('label');
  const layout = section.querySelector('.layout-presets'); const heading = section.querySelector('.section-heading');
  if (!motion || !layout || !heading) return;
  const studio = document.createElement('div'); studio.className = 'appearance-studio';
  const title = (text: string): HTMLElement => {const h = document.createElement('h2'); h.textContent = text; return h;};
  const themeChoices = visualChoices(accent, 'themes');
  studio.append(title('Color scheme'), visualChoices(scheme, 'schemes'), title('Themes'), themeChoices);
  const themes = savedThemes();
  function addCustomChoice(theme: CustomTheme): void {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'custom-theme';
    button.style.setProperty('--custom-orb', theme.color);
    button.innerHTML = '<span class="theme-orbs" aria-hidden="true"><i></i><i></i></span>';
    const name = document.createElement('strong'); name.textContent = theme.name; button.append(name);
    button.setAttribute('aria-pressed', String(storageGet('router-custom-theme-color') === theme.color));
    button.addEventListener('click', () => {
      storageSet('router-custom-theme-color', theme.color); applyDashboardPalette();
      themeChoices.querySelectorAll('button').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
    });
    themeChoices.append(button);
  }
  themes.forEach(addCustomChoice);
  const creator = document.createElement('details'); creator.className = 'theme-creator';
  creator.innerHTML = '<summary>Create theme</summary><div class="theme-create-fields"><label>Theme name<input aria-label="Theme name" maxlength="40" placeholder="My theme"></label><label>Palette color<input aria-label="Palette color" type="color" value="#9ba7ff"></label><button type="button">Save theme</button></div><p role="status" class="field-note"></p>';
  creator.querySelector('button')!.addEventListener('click', () => {
    const name = creator.querySelector<HTMLInputElement>('input:not([type=color])')!.value.trim();
    const feedback = creator.querySelector('p')!;
    if (!name) {feedback.textContent = 'Enter a theme name.'; return;}
    if (themes.length >= 12) {feedback.textContent = 'Up to 12 custom themes can be saved.'; return;}
    const theme = {name, color: creator.querySelector<HTMLInputElement>('[type=color]')!.value};
    themes.push(theme); storageSet('router-custom-themes', JSON.stringify(themes)); addCustomChoice(theme); feedback.textContent = `${name} saved locally.`;
  });
  studio.append(creator, title('Interface'));
  const sources = document.createElement('div'); sources.hidden = true; sources.append(scheme, accent);
  const rows = document.createElement('div'); rows.className = 'settings-rows';
  controls.forEach(source => {
    const label = source.closest('label')!; const name = label.childNodes[0]?.textContent?.trim() ?? 'Setting';
    const row = document.createElement('div'); row.className = 'settings-row';
    const text = document.createElement('strong'); text.textContent = name; source.setAttribute('aria-label', name);
    row.append(text, source.closest('.web-select') ?? source); rows.append(row);
  });
  const widthRow = document.createElement('label'); widthRow.className = 'settings-row'; widthRow.textContent = 'Content width';
  const widthSelect = document.createElement('select'); widthSelect.setAttribute('aria-label', 'Content width');
  widthSelect.innerHTML = '<option value="comfortable">Comfortable</option><option value="wide">Wide</option>';
  widthSelect.value = document.body.dataset.contentWidth ?? 'wide';
  widthSelect.addEventListener('change', () => {document.body.dataset.contentWidth = widthSelect.value; storageSet('router-content-width', widthSelect.value);});
  widthRow.append(widthSelect); rows.append(widthRow); studio.append(rows, title('Layout'), layout, title('Motion'), motion);
  section.replaceChildren(heading, studio, sources);
}

function polishHome(context: DashboardPresentation): void {
  const home = document.querySelector<HTMLElement>('.home-page'); if (!home) return;
  const emblem = home.querySelector('.connection-emblem');
  if (emblem && !emblem.querySelector('svg')) emblem.insertAdjacentHTML('beforeend', '<svg class="connection-ring" viewBox="0 0 160 160" aria-hidden="true"><circle class="ring-track" cx="80" cy="80" r="74"/><circle class="ring-progress" cx="80" cy="80" r="74"/></svg>');
  if (!home.querySelector('.visual-status-strip')) {
    const strip = document.createElement('div'); strip.className = 'visual-status-strip';
    const profile = context.snapshot.profiles.find(item => item.id === context.snapshot.activeProfileId);
    const provider = context.snapshot.providers.find(item => item.id === profile?.providerId);
    const configKnown = context.config !== null && !context.configUnavailable;
    const routes = configKnown && Array.isArray(context.config?.routes) ? context.config.routes : [];
    const routeProviders = [...new Set(routes.map(route => String(route.provider ?? 'direct')))];
    const latency = context.status?.latency_ms;
    const values = context.desktop ? [
      ['Preset', configKnown ? String(context.config?.preset ?? 'Custom routing') : 'Unknown'],
      ['Providers', configKnown ? routeProviders.join(', ') || 'Direct' : 'Unknown'],
      ['Routing', configKnown ? `${routes.length} routes` : 'Unknown'],
      ['Latency', typeof latency === 'number' && Number.isFinite(latency) ? `${latency} ms` : 'Not measured'],
    ] : [
      ['Profile', profile?.name ?? 'Not configured'], ['Provider', provider?.name ?? 'Direct'],
      ['Routing', `${profile?.domains.length ?? 0} sites · sample`],
      ['Latency', provider?.latency == null ? 'Not measured' : `${provider.latency} ms · sample`],
    ];
    values.forEach(([label, value]) => {const item = document.createElement('div'); const caption = document.createElement('span'); caption.textContent = label; const text = document.createElement('strong'); text.textContent = value; item.append(caption, text); strip.append(item);});
    home.querySelector('.connection-status')?.before(strip);
  }
  if (!home.querySelector('.preview-activity')) {
    const activity = document.createElement('section'); activity.className = 'preview-activity';
    const title = document.createElement('h2'); title.textContent = 'Dashboard activity';
    const note = document.createElement('p'); note.className = 'muted'; note.textContent = 'Local dashboard actions. Engine traffic counters are not available yet.';
    const list = document.createElement('ol');
    context.snapshot.logs.slice(0, 8).forEach(message => {const row = document.createElement('li'); row.textContent = message; list.append(row);});
    if (!list.children.length) {const row = document.createElement('li'); row.textContent = 'No dashboard actions recorded yet.'; list.append(row);}
    activity.append(title, note, list); home.append(activity);
  }
}

export function polishDashboard(context: DashboardPresentation): void {
  document.body.classList.add(...classes);
  document.body.dataset.contentWidth ??= storageGet('router-content-width') === 'comfortable' ? 'comfortable' : 'wide';
  document.querySelectorAll<HTMLAnchorElement>('.rail nav a').forEach(link => {if (!link.querySelector('svg')) link.prepend(icon(link.hash.slice(1)));});
  if (context.page === 'Profiles') polishProfiles();
   if (context.page === 'Providers') polishProviders(context.desktop, context.snapshot.providers);
  if (context.page === 'Appearance') polishAppearance();
  if (context.page === 'Home') polishHome(context);
  if (context.page === 'Connectivity') {
    const section = document.querySelector<HTMLElement>('#main .page-section'); section?.classList.add('connectivity-studio');
    document.querySelector('#network-panel')?.classList.add('network-workspace');
  }
  polishEditors();
}

matchMedia('(prefers-color-scheme: light)').addEventListener('change', applyDashboardPalette);
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  document.querySelectorAll<HTMLDetailsElement>('.profile-more[open]').forEach(details => {details.open = false; details.querySelector<HTMLElement>('summary')?.focus();});
});
