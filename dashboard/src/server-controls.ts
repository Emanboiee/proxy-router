import type { Provider } from './controller';

function esc(value: string): string {
  return value.replace(/[&<>"']/g, character =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]!));
}

export function connectionControls(providers: Provider[], selected: string, busy: boolean, connected: boolean): string {
  const provider = providers.find(item => item.id === selected);
  if (!provider) return '';
  const disabled = busy ? 'disabled' : '';
  const selector = providers.length > 1 ? `
    <label for="server-provider">Connection controls</label>
    <select id="server-provider" ${disabled}>
      ${providers.map(item => `<option value="${esc(item.id)}" ${item.id === selected ? 'selected' : ''}>${esc(item.name)}</option>`).join('')}
    </select>` : '';
  let controls: string;
  if (provider.capabilities?.serverSelection) {
    controls = `
      <label for="preferred-server">Preferred server</label>
      <div class="server-preference-row">
        <select id="preferred-server" ${disabled}>
          <option value="">Automatic · router chooses</option>
          ${provider.servers.map(server => `<option value="${esc(server)}" ${server === provider.preferredServer ? 'selected' : ''}>${esc(server)}</option>`).join('')}
        </select>
        <button type="button" data-action="switch-server" ${busy || !connected ? 'disabled' : ''}>Switch now</button>
      </div>
      <p class="muted server-hint">Saving keeps the current connection. Switch now applies the choice; automatic recovery can choose another server.</p>
      <button type="button" class="text-link" data-action="manage-servers" ${disabled}>Browse ${provider.servers.length} installed servers →</button>`;
  } else {
    const hint = provider.capabilities?.reconnect
      ? 'This connection chooses its endpoint automatically.'
      : 'No installed server inventory is available for this connection.';
    controls = `<p class="muted server-hint">${hint}</p>`;
  }
  return `<div class="home-server-controls">${selector}<p class="server-current">${esc(provider.name)} · Current: ${esc(provider.server || 'Unknown')}</p>${controls}</div>`;
}

export function serverInventory(provider: Provider, query: string): string {
  const rows = provider.servers.filter(server => server.toLowerCase().includes(query.trim().toLowerCase()));
  const content = rows.map(server => `<tr>
    <td>${esc(server)}</td><td>${provider.server === server ? 'Current' : '—'}</td>
    <td><button type="button" data-action="prefer-server" data-server="${esc(server)}">${provider.preferredServer === server ? 'Preferred' : 'Prefer'}</button></td>
  </tr>`).join('');
  const empty = rows.length ? '' : '<p>No matching servers. Clear the search to see all installed servers.</p>';
  return `<p class="muted">${rows.length} of ${provider.servers.length} installed servers. Health is not measured by this list.</p>
    <div class="server-inventory-scroll" tabindex="0" role="region" aria-label="Installed servers">
      <table><thead><tr><th scope="col">Server</th><th scope="col">Selection</th><th scope="col">Preference</th></tr></thead>
      <tbody>${content}</tbody></table>${empty}
    </div>`;
}
