/* The administration.

   Two things shape this file. Every table cell carries its column heading in
   data-label, because below 720px the stylesheet turns rows into cards and
   that label is the only thing left saying what a value is. And nothing is
   asked for with prompt(): a share used to be typed as `mueller, #team!` into
   a one-line system box, which is unguessable on any device and uncorrectable
   on a phone. Those are <dialog> elements now, filled from the service, so the
   question "how is that account spelled" never comes up.
   ========================================================================= */

let providers = [];
let allUsers = [];
let allGroups = [];

/* ---------------------------------------------------------------- helpers */

function cell(row, text, label){
  const td = document.createElement('td');
  td.textContent = text;
  if(label) td.dataset.label = label;
  row.appendChild(td);
  return td;
}

/* A round button with a symbol. The words live in title and aria-label: four
   text buttons per row do not fit on a phone, four symbols do. */
function iconBtn(symbol, label, handler, danger){
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'icon-btn' + (danger ? ' danger' : '');
  button.textContent = symbol;
  button.title = label;
  button.setAttribute('aria-label', label);
  button.onclick = handler;
  return button;
}

function actionCell(row, actions){
  const td = document.createElement('td');
  td.className = 'right';
  const box = document.createElement('div');
  box.className = 'row-actions';
  actions.forEach(([symbol, label, handler, danger]) =>
    box.appendChild(iconBtn(symbol, label, handler, danger)));
  td.appendChild(box);
  row.appendChild(td);
  return td;
}

async function guard(action){
  try{ await action(); await loadAll(); }
  catch(err){ show('message', err.message || String(err)); }
}

function formatBytes(bytes){
  if(!bytes) return '—';
  const units = ['B','KB','MB'];
  let value = bytes, unit = 0;
  while(value >= 1024 && unit < units.length - 1){ value /= 1024; unit++; }
  return value.toFixed(unit ? 1 : 0) + ' ' + units[unit];
}

function when(iso){
  return iso ? new Date(iso + 'Z').toLocaleString() : '—';
}

/* ---------------------------------------------------------------- dialogs */

/* Opens a dialog and resolves with the button that closed it. Escape and the
   backdrop both count as cancel - that is what the native element gives us. */
function ask(dialog){
  return new Promise(resolve => {
    dialog.addEventListener('close', () => resolve(dialog.returnValue), { once: true });
    dialog.showModal();
  });
}

/* Shares of one vault. Returns the new set of entries, or null on cancel. */
async function editShares(vault, current){
  const dialog = document.getElementById('shareDialog');
  const list = document.getElementById('shareEntries');
  const subject = document.getElementById('shareSubject');
  const permission = document.getElementById('sharePermission');

  document.getElementById('shareTitle').textContent = 'Freigaben für „' + vault.name + '"';
  document.getElementById('shareHint').textContent =
    'Wer schreiben darf, kennt zwangsläufig das Master-Passwort. Ein Entzug '
    + 'nimmt den Zugriff auf den Dienst, nicht die Kenntnis des Passworts.';

  let entries = current.map(a => ({
    subject_type: a.subject_type, subject: a.subject, permission: a.permission
  }));

  function fillSubjects(){
    subject.innerHTML = '';
    const taken = new Set(entries.map(e => e.subject_type + ':' + e.subject));
    const groupUsers = document.createElement('optgroup');
    groupUsers.label = 'Konten';
    allUsers.forEach(u => {
      if(taken.has('user:' + u.name)) return;
      const option = document.createElement('option');
      option.value = 'user:' + u.name;
      option.textContent = u.name;
      groupUsers.appendChild(option);
    });
    const groupGroups = document.createElement('optgroup');
    groupGroups.label = 'Gruppen';
    allGroups.forEach(g => {
      if(taken.has('group:' + g.name)) return;
      const option = document.createElement('option');
      option.value = 'group:' + g.name;
      option.textContent = '#' + g.name;
      groupGroups.appendChild(option);
    });
    if(groupUsers.children.length) subject.appendChild(groupUsers);
    if(groupGroups.children.length) subject.appendChild(groupGroups);
    document.getElementById('shareAdd').disabled = subject.options.length === 0;
  }

  function draw(){
    list.innerHTML = '';
    if(!entries.length){
      const empty = document.createElement('p');
      empty.className = 'entries-empty';
      empty.textContent = 'Noch niemand. Der Vault ist damit für niemanden zu öffnen.';
      list.appendChild(empty);
    }
    entries.forEach((entry, i) => {
      const box = document.createElement('div');
      box.className = 'entry';

      const name = document.createElement('span');
      name.className = 'entry-name';
      name.textContent = (entry.subject_type === 'group' ? '#' : '') + entry.subject;

      const select = document.createElement('select');
      select.setAttribute('aria-label', 'Recht für ' + entry.subject);
      [['readwrite','Schreiben'], ['read','Lesen']].forEach(([value, text]) => {
        const option = document.createElement('option');
        option.value = value; option.textContent = text;
        if(entry.permission === value) option.selected = true;
        select.appendChild(option);
      });
      select.onchange = () => { entries[i].permission = select.value; };

      box.append(name, select, iconBtn('✕', 'Entfernen', () => {
        entries.splice(i, 1); draw(); fillSubjects();
      }, true));
      list.appendChild(box);
    });
  }

  document.getElementById('shareAdd').onclick = () => {
    if(!subject.value) return;
    const [type, ...rest] = subject.value.split(':');
    entries.push({ subject_type: type, subject: rest.join(':'), permission: permission.value });
    draw();
    fillSubjects();
  };

  draw();
  fillSubjects();
  return await ask(dialog) === 'save' ? entries : null;
}

/* Ticking a list. Used for group members and for the local groups of an
   account - the same question in both cases: which of these, out of those. */
async function pick(title, hint, options, selected){
  const dialog = document.getElementById('pickDialog');
  const list = document.getElementById('pickList');
  document.getElementById('pickTitle').textContent = title;
  document.getElementById('pickHint').textContent = hint;
  list.innerHTML = '';

  if(!options.length){
    const empty = document.createElement('p');
    empty.className = 'entries-empty';
    empty.textContent = 'Nichts zur Auswahl.';
    list.appendChild(empty);
  }

  const chosen = new Set(selected);
  options.forEach(([value, text, note]) => {
    const label = document.createElement('label');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.value = value;
    box.checked = chosen.has(value);
    const span = document.createElement('span');
    span.textContent = text;
    if(note){
      const kind = document.createElement('span');
      kind.className = 'kind';
      kind.textContent = note;
      span.appendChild(kind);
    }
    label.append(box, span);
    list.appendChild(label);
  });

  if(await ask(dialog) !== 'save') return null;
  return Array.from(list.querySelectorAll('input:checked')).map(box => box.value);
}

const SETTINGS = [
  ['origin', 'Öffentliche Adresse', 'text'],
  ['session_hours', 'Sitzung (Stunden)', 'number'],
  ['session_idle_minutes', 'Leerlauf (Minuten)', 'number'],
  ['max_size_bytes', 'Vault-Limit (Bytes)', 'number'],
  ['lock_ttl_seconds', 'Sperre (Sekunden)', 'number'],
  ['history_warn_bytes', 'Historie-Warnung (Bytes)', 'number'],
  ['host', 'Host', 'text'],
  ['port', 'Port', 'number'],
  ['workers', 'Worker', 'number'],
  ['forwarded_allow_ips', 'Proxy-Adressen', 'text'],
  ['proxy_headers', 'Hinter Reverse Proxy', 'checkbox'],
];

/* ------------------------------------------------------------------ load */

async function loadAll(){
  const [providerList, allow, users, groups, vaultList, settings] = await Promise.all([
    api('/api/providers'), api('/api/allowlist'), api('/api/users'),
    api('/api/groups'), api('/api/vaults'), api('/api/settings')
  ]);
  providers = providerList;
  allUsers = users;
  allGroups = groups;

  // ---- providers -------------------------------------------------------
  const providerBody = document.querySelector('#providers tbody');
  providerBody.innerHTML = '';
  providers.forEach(provider => {
    const row = document.createElement('tr');
    cell(row, provider.name + (provider.is_primary ? ' (primär)' : ''), 'Name');
    cell(row, provider.kind, 'Art');
    const where = cell(row, provider.kind === 'microsoft'
      ? (provider.tenant || '—') : provider.issuer, 'Tenant / Issuer');
    where.title = 'Umleitung: ' + provider.redirect_uri;
    cell(row, String(provider.allowlisted), 'Liste');
    cell(row, String(provider.accounts), 'Konten');
    cell(row, provider.sync_groups ? 'an' : 'aus', 'Sync');
    actionCell(row, [
      ['⧉', 'Umleitung kopieren', () => navigator.clipboard.writeText(provider.redirect_uri)
        .then(() => show('message', provider.redirect_uri, 'ok'))
        .catch(() => show('message', provider.redirect_uri, 'ok'))],
      ['⟳', provider.sync_groups ? 'Gruppen-Sync abschalten' : 'Gruppen-Sync einschalten',
        () => guard(() => api('/api/providers/' + provider.id, { method:'PATCH',
          body: JSON.stringify({ sync_groups: !provider.sync_groups }) }))],
      ...(provider.is_primary ? [] : [['★', 'Zum primären Anbieter machen',
        () => guard(() => api('/api/providers/' + provider.id, { method:'PATCH',
          body: JSON.stringify({ is_primary: true }) }))]]),
      ['◉', provider.enabled ? 'Abschalten' : 'Einschalten',
        () => guard(() => api('/api/providers/' + provider.id, { method:'PATCH',
          body: JSON.stringify({ enabled: !provider.enabled }) }))],
      ['✕', 'Löschen', () => { if(confirm('Anbieter ' + provider.name + ' löschen?'))
        guard(() => api('/api/providers/' + provider.id, { method:'DELETE' })); }, true]
    ]);
    providerBody.appendChild(row);
  });

  const select = document.getElementById('aProvider');
  select.innerHTML = '';
  providers.forEach(p => {
    const option = document.createElement('option');
    option.value = p.id; option.textContent = p.name;
    if(p.is_primary) option.selected = true;
    select.appendChild(option);
  });

  // ---- allowlist -------------------------------------------------------
  const allowBody = document.querySelector('#allowlist tbody');
  allowBody.innerHTML = '';
  allow.forEach(entry => {
    const row = document.createElement('tr');
    cell(row, entry.email, 'Adresse');
    cell(row, (providers.find(p => p.id === entry.provider_id) || {}).name || '?', 'Anbieter');
    cell(row, entry.is_admin ? 'Administrator' : 'Benutzer', 'Rolle');
    cell(row, entry.account_id ? 'angemeldet ' + when(entry.last_login_at)
                               : 'noch nie angemeldet', 'Konto');
    cell(row, entry.note || '—', 'Notiz');
    actionCell(row, [
      ['★', entry.is_admin ? 'Zum Benutzer machen' : 'Zum Administrator machen',
        () => guard(() => api('/api/allowlist/' + entry.id, { method:'PATCH',
          body: JSON.stringify({ is_admin: !entry.is_admin }) }))],
      ['✕', 'Von der Liste nehmen', () => {
        if(confirm(entry.email + ' von der Liste nehmen? Ein vorhandenes Konto wird gesperrt.'))
          guard(() => api('/api/allowlist/' + entry.id, { method:'DELETE' }));
      }, true]
    ]);
    allowBody.appendChild(row);
  });

  // ---- accounts --------------------------------------------------------
  const userBody = document.querySelector('#users tbody');
  userBody.innerHTML = '';
  users.forEach(user => {
    const row = document.createElement('tr');
    cell(row, user.name + (user.is_admin ? ' (Admin)' : ''), 'Name');
    cell(row, user.email, 'Adresse');
    cell(row, user.provider, 'Anbieter');
    cell(row, user.groups.join(', ') || '—', 'Gruppen');
    cell(row, user.is_active ? 'aktiv' : 'gesperrt', 'Status');
    cell(row, when(user.last_login_at), 'Letzte Anmeldung');
    actionCell(row, [
      ['✎', 'Lokale Gruppen zuweisen', async () => {
        const local = allGroups.filter(g => g.source === 'local');
        const chosen = await pick(
          'Gruppen von ' + user.name,
          'Nur lokale Gruppen. Anbieter-Gruppen kommen beim Login und sind hier nicht änderbar.',
          local.map(g => [g.name, g.name, g.description || null]),
          user.groups.filter(name => local.some(g => g.name === name)));
        if(chosen === null) return;
        guard(() => api('/api/users/' + user.id, { method:'PATCH',
          body: JSON.stringify({ groups: chosen }) }));
      }],
      ['⎋', 'Sitzungen beenden', () => guard(() =>
        api('/api/users/' + user.id + '/revoke-sessions', { method:'POST' }))],
      ['⏻', user.is_active ? 'Konto sperren' : 'Konto freigeben',
        () => guard(() => api('/api/users/' + user.id, { method:'PATCH',
          body: JSON.stringify({ is_active: !user.is_active }) }))],
      ['✕', 'Konto löschen', () => { if(confirm('Konto ' + user.name + ' löschen?'))
        guard(() => api('/api/users/' + user.id, { method:'DELETE' })); }, true]
    ]);
    userBody.appendChild(row);
  });

  // ---- groups ----------------------------------------------------------
  const groupBody = document.querySelector('#groups tbody');
  groupBody.innerHTML = '';
  groups.forEach(group => {
    const row = document.createElement('tr');
    cell(row, group.name, 'Gruppe').title = group.description || '';
    const origin = cell(row, group.source === 'local' ? 'lokal'
      : 'Anbieter ' + (group.provider || '?') + (group.frozen ? ' (eingefroren)' : ''),
      'Herkunft');
    origin.title = group.frozen
      ? 'Der Anbieter synchronisiert nicht mehr; die Mitgliedschaft ist der letzte bekannte Stand.'
      : '';
    cell(row, group.members.join(', ') || '—', 'Mitglieder');
    cell(row, group.source === 'local' ? '—' : when(group.last_synced_at), 'Letzter Sync');
    const actions = [];
    if(group.source === 'local'){
      actions.push(['✎', 'Mitglieder wählen', async () => {
        const chosen = await pick(
          'Mitglieder von ' + group.name,
          'Konten, die zu dieser Gruppe gehören.',
          allUsers.map(u => [u.name, u.name, u.email]),
          group.members);
        if(chosen === null) return;
        guard(() => api('/api/groups/' + group.id, { method:'PATCH',
          body: JSON.stringify({ members: chosen }) }));
      }]);
    }
    actions.push(['✕', 'Gruppe löschen', () => {
      if(confirm('Gruppe ' + group.name + ' löschen?'))
        guard(() => api('/api/groups/' + group.id, { method:'DELETE' }));
    }, true]);
    actionCell(row, actions);
    groupBody.appendChild(row);
  });

  // ---- vaults ----------------------------------------------------------
  const vaultBody = document.querySelector('#vaults tbody');
  vaultBody.innerHTML = '';
  for(const vault of vaultList){
    const row = document.createElement('tr');
    cell(row, vault.name, 'Vault').title = vault.description || '';
    const access = await api('/api/vaults/' + vault.id + '/access');
    cell(row, access.length
      ? access.map(a => (a.subject_type === 'group' ? '#' : '') + a.subject
                        + (a.permission === 'read' ? ' (lesen)' : '')).join(', ')
      : 'niemand', 'Freigaben');
    cell(row, vault.locked_by ? 'in Bearbeitung: ' + vault.locked_by
            : vault.empty ? 'leer' : 'belegt', 'Zustand');
    cell(row, formatBytes(vault.size_bytes), 'Größe');
    cell(row, vault.generations
      ? vault.generations + ' × ' + formatBytes(vault.history_bytes) : '—', 'Historie');

    const actions = [
      ['⇄', 'Freigaben bearbeiten', async () => {
        const entries = await editShares(vault, access);
        if(entries === null) return;
        guard(() => api('/api/vaults/' + vault.id + '/access',
          { method:'PUT', body: JSON.stringify({ entries }) }));
      }]
    ];
    if(vault.generations) actions.push(['↺', 'Historie ansehen', () => showHistory(vault)]);
    if(vault.locked_by) actions.push(['⊘', 'Sperre brechen', () => guard(() =>
      api('/api/vaults/' + vault.id + '/lock?force=1', { method:'DELETE' }))]);
    actions.push(['✕', 'Vault löschen', () => {
      if(confirm('Vault ' + vault.name + ' mit allen Daten löschen?'))
        guard(() => api('/api/vaults/' + vault.id, { method:'DELETE' }));
    }, true]);
    actionCell(row, actions);
    vaultBody.appendChild(row);
  }

  // ---- settings --------------------------------------------------------
  const form = document.getElementById('settingsForm');
  form.innerHTML = '';
  SETTINGS.forEach(([key, label, type]) => {
    const field = document.createElement('label');
    field.className = 'field' + (type === 'checkbox' ? ' check' : '');
    const caption = document.createElement('span');
    caption.textContent = label;
    const input = document.createElement('input');
    input.type = type;
    input.dataset.key = key;
    if(type === 'checkbox'){
      input.checked = !!settings[key];
      field.append(input, caption);
    } else {
      input.value = settings[key];
      field.append(caption, input);
    }
    form.appendChild(field);
  });
}


/* --------------------------------------------------------------- history */

async function showHistory(vault){
  const dialog = document.getElementById('historyDialog');
  document.getElementById('historyTitle').textContent = 'Historie: ' + vault.name;
  const body = document.querySelector('#history tbody');
  body.innerHTML = '';
  const data = await api('/api/vaults/' + vault.id + '/history');
  const summary = document.getElementById('historySummary');
  summary.textContent = data.generations.length + ' Generation(en), zusammen '
    + formatBytes(data.total_bytes)
    + (data.warn ? ' — mehr als ' + formatBytes(data.warn_bytes)
                 + '. Nichts verfällt von selbst; aufgeräumt wird hier.' : '');
  summary.className = data.warn ? 'msg show error' : 'note';

  data.generations.forEach(generation => {
    const row = document.createElement('tr');
    cell(row, '#' + generation.seq, 'Nr.');
    cell(row, when(generation.created_at), 'Zeitpunkt');
    cell(row, generation.author || '—', 'Wer');
    cell(row, formatBytes(generation.size_bytes), 'Größe');
    cell(row, generation.note || '—', 'Vermerk');
    actionCell(row, [
      ['⇩', 'Herunterladen', () => {
        location.href = '/api/vaults/' + vault.id + '/history/' + generation.seq + '/content';
      }],
      ['↩', 'Wiederherstellen', () => guard(async () => {
        const lock = await api('/api/vaults/' + vault.id + '/lock', { method:'POST' });
        try{
          await api('/api/vaults/' + vault.id + '/history/' + generation.seq + '/restore',
                    { method:'POST', headers: {'X-Vault-Lock': lock.token} });
        } finally {
          await api('/api/vaults/' + vault.id + '/lock',
                    { method:'DELETE', headers: {'X-Vault-Lock': lock.token} });
        }
        dialog.close('done');
        show('message', 'Stand #' + generation.seq + ' wiederhergestellt — als neue Generation.', 'ok');
      })],
      ['✕', 'Generation löschen', () => {
        if(confirm('Generation #' + generation.seq + ' endgültig löschen?'))
          guard(async () => {
            await api('/api/vaults/' + vault.id + '/history/' + generation.seq, { method:'DELETE' });
            dialog.close('done');
          });
      }, true]
    ]);
    body.appendChild(row);
  });

  dialog.showModal();
}

/* ------------------------------------------------------------------ forms */

/* Microsoft wants a tenant, a generic provider an issuer URL, Google neither.
   One field, and its label says which of the three is meant right now. */
function updateProviderForm(){
  const kind = document.getElementById('pKind').value;
  const label = document.getElementById('pWhereLabel');
  const input = document.getElementById('pTenant');
  const field = input.closest('.field');
  if(kind === 'microsoft'){
    label.textContent = 'Tenant';
    input.placeholder = 'contoso.onmicrosoft.com';
    field.hidden = false;
  } else if(kind === 'generic'){
    label.textContent = 'Issuer-URL';
    input.placeholder = 'https://idp.example';
    field.hidden = false;
  } else {
    field.hidden = true;
  }
}

document.getElementById('pKind').onchange = updateProviderForm;
updateProviderForm();

document.getElementById('btnAddProvider').onclick = () => guard(async () => {
  const kind = document.getElementById('pKind').value;
  const where = document.getElementById('pTenant').value.trim();
  await api('/api/providers', { method:'POST', body: JSON.stringify({
    name: document.getElementById('pName').value.trim(),
    kind,
    tenant: kind === 'microsoft' ? where : null,
    issuer: kind === 'generic' ? where : '',
    client_id: document.getElementById('pClientId').value.trim(),
    client_secret: document.getElementById('pSecret').value,
    sync_groups: document.getElementById('pSync').checked
  })});
  ['pName','pTenant','pClientId','pSecret'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('pSync').checked = false;
});

document.getElementById('btnAddAllow').onclick = () => guard(async () => {
  await api('/api/allowlist', { method:'POST', body: JSON.stringify({
    provider_id: Number(document.getElementById('aProvider').value),
    email: document.getElementById('aEmail').value.trim(),
    is_admin: document.getElementById('aAdmin').checked,
    note: document.getElementById('aNote').value.trim()
  })});
  document.getElementById('aEmail').value = '';
  document.getElementById('aNote').value = '';
  document.getElementById('aAdmin').checked = false;
});

document.getElementById('btnAddGroup').onclick = () => guard(async () => {
  await api('/api/groups', { method:'POST', body: JSON.stringify({
    name: document.getElementById('newGroupName').value.trim(),
    description: document.getElementById('newGroupDesc').value.trim()
  })});
  document.getElementById('newGroupName').value = '';
  document.getElementById('newGroupDesc').value = '';
});

document.getElementById('btnAddVault').onclick = () => guard(async () => {
  await api('/api/vaults', { method:'POST', body: JSON.stringify({
    name: document.getElementById('newVaultName').value.trim(),
    description: document.getElementById('newVaultDesc').value.trim()
  })});
  document.getElementById('newVaultName').value = '';
  document.getElementById('newVaultDesc').value = '';
});

document.getElementById('btnSaveSettings').onclick = () => guard(async () => {
  const payload = {};
  document.querySelectorAll('#settingsForm input').forEach(input => {
    const key = input.dataset.key;
    payload[key] = input.type === 'checkbox' ? input.checked
                 : input.type === 'number' ? Number(input.value) : input.value.trim();
  });
  await api('/api/settings', { method:'PUT', body: JSON.stringify(payload) });
  show('message', 'Einstellungen gespeichert.', 'ok');
});

document.getElementById('logout').onclick = async () => {
  await api('/auth/logout', { method:'POST' });
  location.href = '/login';
};

loadAll().catch(err => show('message', err.message || String(err)));
