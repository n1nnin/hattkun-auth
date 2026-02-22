// GitHub OAuth proxy for Decap CMS
// Deployed as a Cloudflare Worker
// Required env vars: GITHUB_CLIENT_ID (vars), GITHUB_CLIENT_SECRET (secret)

const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';
const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const ALLOWED_ORIGINS = [
  'https://hattkun-programming.moroku0519.workers.dev',
  'http://localhost:4321',
];
const CMS_ORIGIN = 'https://hattkun-programming.moroku0519.workers.dev';

function corsHeaders(origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    // Step 1: Redirect to GitHub OAuth
    if (url.pathname === '/auth') {
      const scope = url.searchParams.get('scope') || 'repo';
      const state = crypto.randomUUID();

      // Store state in a short-lived cookie for CSRF validation
      const authUrl = new URL(GITHUB_AUTHORIZE_URL);
      authUrl.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
      authUrl.searchParams.set('redirect_uri', `${url.origin}/callback`);
      authUrl.searchParams.set('scope', scope);
      authUrl.searchParams.set('state', state);

      return new Response(null, {
        status: 302,
        headers: {
          'Location': authUrl.toString(),
          'Set-Cookie': `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
        },
      });
    }

    // Step 2: Handle callback from GitHub
    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      const returnedState = url.searchParams.get('state');

      if (!code) {
        return new Response('Missing code parameter', { status: 400 });
      }

      // Validate state parameter (CSRF protection)
      const cookies = request.headers.get('Cookie') || '';
      const stateMatch = cookies.match(/oauth_state=([^;]+)/);
      const savedState = stateMatch ? stateMatch[1] : null;

      if (!savedState || savedState !== returnedState) {
        return new Response('Invalid state parameter', { status: 403 });
      }

      // Exchange code for access token
      const tokenRes = await fetch(GITHUB_TOKEN_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
        }),
      });

      const tokenData = await tokenRes.json();

      if (tokenData.error) {
        return new Response(`OAuth error: ${tokenData.error_description || tokenData.error}`, {
          status: 400,
        });
      }

      // Return token to CMS via postMessage (Decap CMS handshake protocol)
      const safeToken = tokenData.access_token.replace(/[^a-zA-Z0-9_-]/g, '');
      const html = `<!doctype html>
<html>
<head><title>認証完了</title></head>
<body>
<script>
(function() {
  var provider = 'github';
  var token = '${safeToken}';
  var cmsOrigin = '${CMS_ORIGIN}';

  if (!window.opener) {
    document.getElementById('msg').textContent =
      '認証エラー: ポップアップウィンドウが見つかりません。管理画面を開き直してください。';
    return;
  }

  // Step 1: Send handshake message to CMS
  window.opener.postMessage('authorizing:' + provider, cmsOrigin);

  // Step 2: Wait for handshake response, then send auth token
  window.addEventListener('message', function handler(e) {
    if (e.data === 'authorizing:' + provider) {
      window.removeEventListener('message', handler, false);
      var data = JSON.stringify({ token: token, provider: provider });
      window.opener.postMessage(
        'authorization:' + provider + ':success:' + data,
        e.origin
      );
      setTimeout(function() { window.close(); }, 1000);
    }
  }, false);
})();
</script>
<p id="msg">認証が完了しました。このウィンドウは自動的に閉じます。</p>
</body>
</html>`;

      return new Response(html, {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Set-Cookie': 'oauth_state=; Path=/; HttpOnly; Secure; Max-Age=0',
        },
      });
    }

    // Health check
    if (url.pathname === '/') {
      return new Response('OAuth proxy is running', {
        headers: { 'Content-Type': 'text/plain', ...corsHeaders(origin) },
      });
    }

    return new Response('Not found', { status: 404 });
  },
};
