import type {Provider} from './controller';
const esc=(value:string)=>value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
export function connectionControls(providers: Provider[], selected: string, busy: boolean, connected: boolean): string {
 const provider=providers.find(p=>p.id===selected);
 if(!provider)return '';
 const disabled=busy?'disabled':'';
 const selector=providers.length>1?'<label for="server-provider">Connection controls</label><select id="server-provider" '+disabled+'>'+providers.map(p=>'<option value="'+esc(p.id)+'" '+(p.id===selected?'selected':'')+'>'+esc(p.name)+'</option>').join('')+'</select>':'';
 return '<div class="home-server-controls">'+selector+'<p class="server-current">'+esc(provider.name)+' · Current: '+esc(provider.server||'Unknown')+'</p>'+
 (provider.capabilities?.serverSelection?'<label for="preferred-server">Preferred server</label><div class="server-preference-row"><select id="preferred-server" '+disabled+'><option value="">Automatic · router chooses</option>'+provider.servers.map(server=>'<option value="'+esc(server)+'" '+(server===provider.preferredServer?'selected':'')+'>'+esc(server)+'</option>').join('')+'</select><button type="button" data-action="switch-server" '+(busy||!connected?'disabled':'')+'>Switch now</button></div><p class="muted server-hint">Saving keeps the current connection. Switch now applies the choice; automatic recovery can choose another server.</p><button type="button" class="text-link" data-action="manage-servers" '+disabled+'>Browse '+provider.servers.length+' installed servers →</button>':
 '<p class="muted server-hint">'+(provider.capabilities?.reconnect?'This connection chooses its endpoint automatically.':'No installed server inventory is available for this connection.')+'</p>')+'</div>';
}
export function serverInventory(provider: Provider, query: string): string {
 const rows=provider.servers.filter(s=>s.toLowerCase().includes(query.trim().toLowerCase()));
 return '<p class="muted">'+rows.length+' of '+provider.servers.length+' installed servers. Health is not measured by this list.</p><div class="server-inventory-scroll" tabindex="0" role="region" aria-label="Installed servers"><table><thead><tr><th scope="col">Server</th><th scope="col">Selection</th><th scope="col">Preference</th></tr></thead><tbody>'+rows.map(s=>'<tr><td>'+esc(s)+'</td><td>'+(provider.server===s?'Current':'—')+'</td><td><button type="button" data-action="prefer-server" data-server="'+esc(s)+'">'+(provider.preferredServer===s?'Preferred':'Prefer')+'</button></td></tr>').join('')+'</tbody></table>'+(rows.length?'':'<p>No matching servers. Clear the search to see all installed servers.</p>')+'</div>';
}
