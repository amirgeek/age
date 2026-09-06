const crypto = require('crypto');

const COOKIE_NAME = 'marea_cotizador_session';

function json(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

function getCookie(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').map((item) => item.trim()).find((item) => item.startsWith(`${COOKIE_NAME}=`))?.slice(COOKIE_NAME.length + 1);
}

module.exports = (req, res) => {
  const secret = process.env.COTIZADOR_SESSION_SECRET;
  if (!secret) return json(res, 503, { authenticated: false });

  if (req.method === 'POST') {
    return json(res, 200, { ok: true }, { 'Set-Cookie': `${COOKIE_NAME}=; Path=/cotizador; HttpOnly; Secure; SameSite=Strict; Max-Age=0` });
  }

  const token = getCookie(req);
  if (!token || !token.includes('.')) return json(res, 401, { authenticated: false });
  const [payload, receivedSignature] = token.split('.');
  const expectedSignature = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  if (receivedSignature.length !== expectedSignature.length || !crypto.timingSafeEqual(Buffer.from(receivedSignature), Buffer.from(expectedSignature))) return json(res, 401, { authenticated: false });

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!session.exp || Date.now() > session.exp) return json(res, 401, { authenticated: false });
  } catch { return json(res, 401, { authenticated: false }); }
  return json(res, 200, { authenticated: true });
};
