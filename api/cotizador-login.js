const crypto = require('crypto');

const COOKIE_NAME = 'marea_cotizador_session';
const MAX_AGE_SECONDS = 60 * 60 * 8;

function encode(value) {
  return Buffer.from(value).toString('base64url');
}

function sign(value, secret) {
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const password = process.env.COTIZADOR_ACCESS_PASSWORD;
  const secret = process.env.COTIZADOR_SESSION_SECRET;
  if (!password || !secret) return json(res, 503, { error: 'Cotizador no configurado' });

  let body = '';
  for await (const chunk of req) body += chunk;
  let suppliedPassword = '';
  try { suppliedPassword = JSON.parse(body).password || ''; } catch { return json(res, 400, { error: 'Solicitud inválida' }); }

  const valid = suppliedPassword.length === password.length && crypto.timingSafeEqual(Buffer.from(suppliedPassword), Buffer.from(password));
  if (!valid) return json(res, 401, { error: 'Contraseña incorrecta' });

  const payload = encode(JSON.stringify({ exp: Date.now() + MAX_AGE_SECONDS * 1000 }));
  const token = `${payload}.${sign(payload, secret)}`;
  const cookie = `${COOKIE_NAME}=${token}; Path=/cotizador; HttpOnly; Secure; SameSite=Strict; Max-Age=${MAX_AGE_SECONDS}`;
  return json(res, 200, { ok: true }, { 'Set-Cookie': cookie });
};
