const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
const keysBody = document.querySelector('#keys-body');
const logsBody = document.querySelector('#logs-body');
const searchInput = document.querySelector('#key-search');
const adminError = document.querySelector('#admin-error');
const createDialog = document.querySelector('#create-dialog');
const secretDialog = document.querySelector('#secret-dialog');
let keys = [];

const esc = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]);
const when = (value) => value ? new Date(value).toLocaleString() : 'Never';

async function api(path, options = {}) {
  const headers = { ...(options.body ? { 'content-type': 'application/json' } : {}), ...(csrf ? { 'x-csrf-token': csrf } : {}), ...options.headers };
  const response = await fetch(path, { ...options, headers });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const details = payload?.error?.details;
    const message = Array.isArray(details) && details.length ? details.map((item) => `${item.field}: ${item.message}`).join(' · ') : payload?.error?.message || `Request failed (${response.status})`;
    throw new Error(message);
  }
  return payload;
}

function showAdminError(message) {
  adminError.textContent = message;
  adminError.classList.remove('hidden');
  setTimeout(() => adminError.classList.add('hidden'), 6000);
}

function statusBadge(status) {
  return `<span class="status status-${esc(status)}"><i></i>${esc(status)}</span>`;
}

function renderKeys() {
  const query = searchInput.value.trim().toLowerCase();
  const filtered = keys.filter((key) => `${key.label} ${key.key_prefix} ${key.contact_email || ''}`.toLowerCase().includes(query));
  if (!filtered.length) {
    keysBody.innerHTML = '<tr><td colspan="6" class="loading-cell">No matching API keys.</td></tr>';
    return;
  }
  keysBody.innerHTML = filtered.map((key) => `
    <tr>
      <td><div class="key-cell"><strong>${esc(key.label)}</strong><code>${esc(key.key_prefix)}</code><small>${esc(key.gmail_hint || 'QR-only / no Gmail')}</small></div></td>
      <td><div class="scope-list">${key.scopes.map((scope) => `<span>${esc(scope)}</span>`).join('')}</div></td>
      <td>${statusBadge(key.status)}</td>
      <td><div class="date-cell"><strong>${esc(when(key.expires_at))}</strong><small>${key.status === 'active' ? `${Math.ceil(key.expires_in_seconds / 3600)}h remaining` : key.status}</small></div></td>
      <td><div class="usage-cell"><strong>${Number(key.requests_count).toLocaleString()}</strong><small>Last: ${esc(when(key.last_used_at))}</small></div></td>
      <td><details class="row-menu"><summary>•••</summary><div>
        <button data-action="extend" data-id="${esc(key.id)}">Extend</button>
        <button data-action="rotate" data-id="${esc(key.id)}">Rotate</button>
        ${key.status !== 'revoked' ? `<button class="danger" data-action="revoke" data-id="${esc(key.id)}">Revoke</button>` : ''}
      </div></details></td>
    </tr>`).join('');
}

function renderLogs(logs) {
  if (!logs.length) {
    logsBody.innerHTML = '<tr><td colspan="5" class="loading-cell">No API activity yet.</td></tr>';
    return;
  }
  logsBody.innerHTML = logs.map((log) => `
    <tr><td>${esc(when(log.created_at))}</td><td><strong>${esc(log.key_label || 'system / admin')}</strong><small class="block">${esc(log.key_prefix || '')}</small></td>
    <td><span class="method ${String(log.method).toLowerCase()}">${esc(log.method)}</span> <code>${esc(log.endpoint)}</code></td>
    <td><span class="http-status ${log.status < 400 ? 'ok' : 'bad'}">${esc(log.status)}</span></td><td>${esc(log.latency_ms)} ms</td></tr>`).join('');
}

async function load() {
  try {
    const [keyData, dashboard] = await Promise.all([api('/api/v1/admin/keys'), api('/api/v1/admin/dashboard')]);
    keys = keyData.keys;
    renderKeys();
    renderLogs(dashboard.logs);
    document.querySelector('#stat-total').textContent = Number(dashboard.stats.total_keys).toLocaleString();
    document.querySelector('#stat-active').textContent = Number(dashboard.stats.active_keys).toLocaleString();
    document.querySelector('#stat-requests').textContent = Number(dashboard.stats.requests_today).toLocaleString();
    document.querySelector('#stat-verified').textContent = Number(dashboard.stats.verifications_today).toLocaleString();
  } catch (error) {
    showAdminError(error.message);
  }
}

searchInput.addEventListener('input', renderKeys);
document.querySelector('#show-create').addEventListener('click', () => createDialog.showModal());
document.querySelectorAll('[data-close]').forEach((button) => button.addEventListener('click', () => createDialog.close()));
document.querySelector('[data-secret-close]').addEventListener('click', () => secretDialog.close());

function showSecret(secret) {
  document.querySelector('#admin-issued-key').textContent = secret;
  secretDialog.showModal();
}

document.querySelector('#admin-copy-key').addEventListener('click', async (event) => {
  await navigator.clipboard.writeText(document.querySelector('#admin-issued-key').textContent);
  event.currentTarget.textContent = 'Copied!';
  setTimeout(() => { event.currentTarget.textContent = 'Copy'; }, 1400);
});

document.querySelector('#admin-create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const scopes = [];
  if (formData.get('scope_qr')) scopes.push('qr');
  if (formData.get('scope_verify')) scopes.push('verify');
  const body = {
    label: formData.get('label') || '', contact_email: formData.get('contact_email') || '',
    gmail: formData.get('gmail') || '', gmail_app_password: formData.get('gmail_app_password') || '',
    default_upi_id: formData.get('default_upi_id') || '', payee_name: formData.get('payee_name') || '',
    allowed_senders: formData.get('allowed_senders') || '', expires_in_hours: Number(formData.get('expires_in_hours')), scopes,
  };
  const errorBox = document.querySelector('#create-error');
  errorBox.classList.add('hidden');
  try {
    const payload = await api('/api/v1/admin/keys', { method: 'POST', body: JSON.stringify(body) });
    createDialog.close();
    form.reset();
    showSecret(payload.api_key);
    await load();
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove('hidden');
  }
});

keysBody.addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const { action, id } = button.dataset;
  try {
    if (action === 'revoke') {
      if (!confirm('Revoke this API key immediately? This cannot be undone.')) return;
      await api(`/api/v1/admin/keys/${id}/revoke`, { method: 'POST', body: '{}' });
    }
    if (action === 'extend') {
      const hours = Number(prompt('Extend by how many hours?', '168'));
      if (!Number.isInteger(hours) || hours < 1) return;
      await api(`/api/v1/admin/keys/${id}/extend`, { method: 'POST', body: JSON.stringify({ hours }) });
    }
    if (action === 'rotate') {
      if (!confirm('Rotate this key? The current key will be revoked immediately.')) return;
      const payload = await api(`/api/v1/admin/keys/${id}/rotate`, { method: 'POST', body: '{}' });
      showSecret(payload.api_key);
    }
    await load();
  } catch (error) {
    showAdminError(error.message);
  }
});

load();
