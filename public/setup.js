const form = document.querySelector('#setup-form');
const errorBox = document.querySelector('#form-error');
const result = document.querySelector('#key-result');

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove('hidden');
}

function errorMessage(payload) {
  const details = payload?.error?.details;
  if (Array.isArray(details) && details.length) return details.map((item) => `${item.field}: ${item.message}`).join(' · ');
  return payload?.error?.message || 'Unable to create the API key.';
}

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.classList.add('hidden');
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  submit.textContent = 'Encrypting & issuing…';
  const fields = new FormData(form);
  const body = {
    label: fields.get('label') || '',
    contact_email: fields.get('contact_email') || '',
    gmail: fields.get('gmail') || '',
    gmail_app_password: fields.get('gmail_app_password') || '',
    default_upi_id: fields.get('default_upi_id') || '',
    payee_name: fields.get('payee_name') || '',
    allowed_senders: fields.get('allowed_senders') || '',
    expires_in_days: Number(fields.get('expires_in_days')),
    setup_access_code: fields.get('setup_access_code') || '',
    consent: fields.get('consent') === 'on',
  };
  try {
    const response = await fetch('/api/v1/keys', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(errorMessage(payload));
    document.querySelector('#issued-key').textContent = payload.api_key;
    document.querySelector('#key-expiry').textContent = new Date(payload.key.expires_at).toLocaleString();
    form.classList.add('hidden');
    result.classList.remove('hidden');
    result.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (error) {
    showError(error.message);
  } finally {
    submit.disabled = false;
    submit.innerHTML = 'Encrypt settings & create key <span>→</span>';
  }
});

document.querySelector('#copy-key')?.addEventListener('click', async (event) => {
  const value = document.querySelector('#issued-key').textContent;
  await navigator.clipboard.writeText(value);
  event.currentTarget.textContent = 'Copied!';
  setTimeout(() => { event.currentTarget.textContent = 'Copy'; }, 1600);
});
