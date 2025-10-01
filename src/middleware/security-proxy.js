// src/middleware/security-proxy.js
// Security middleware to integrate with Ultraviolet express app.
// - per-session cookie jar (tough-cookie)
// - store jar in session (uses express-session on the app)
// - intercept HTML responses, inject WebRTC/fingerprint blocker
// - strip Set-Cookie / CSP from upstream before sending to client
//
// This file assumes the UV app already uses express-session (if not, add it in the main server).

import { CookieJar } from "tough-cookie";
import { once } from "events";

const INJECT_SNIPPET = `
<!-- injected-by-secure-proxy -->
<script>
(() => {
  // --- WebRTC hard-disable ---
  const disabled = () => { throw new Error('WebRTC disabled by proxy'); };
  try { Object.defineProperty(window, 'RTCPeerConnection', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(window, 'webkitRTCPeerConnection', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(window, 'RTCDataChannel', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(window, 'RTCIceCandidate', { value: disabled, configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'mediaDevices', {
    value: { getUserMedia: () => Promise.reject(new Error('disabled')) }, configurable: false
  }); } catch(e){}

  // --- Block service workers ---
  try { if (navigator.serviceWorker) navigator.serviceWorker.register = () => Promise.reject(new Error('ServiceWorker disabled by proxy')); } catch(e){}
  try { window.navigator.serviceWorker = undefined; } catch(e){}

  // --- Block WebSockets ---
  try { const OldWS = window.WebSocket; window.WebSocket = function(){ throw new Error('WebSocket disabled by proxy'); }; for (let k in OldWS) try { window.WebSocket[k] = OldWS[k]; } catch(e){} } catch(e){}

  // --- Anti-fingerprinting basics (canvas, webgl, navigator) ---
  try { HTMLCanvasElement.prototype.getContext = function(){ return null; }; } catch(e){}
  try { HTMLCanvasElement.prototype.toDataURL = function(){ return ''; }; } catch(e){}
  try { HTMLCanvasElement.prototype.toBlob = function(cb){ if (cb) cb(null); }; } catch(e){}
  try { Object.defineProperty(navigator, 'plugins', { value: [], configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'languages', { value: ['en-US','en'], configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'userAgent', { value: 'Mozilla/5.0 (Win32) ProxyBrowser' , configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'hardwareConcurrency', { value: 2, configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'platform', { value: 'Win32', configurable: false }); } catch(e){}
  try { Object.defineProperty(navigator, 'mimeTypes', { value: [], configurable: false }); } catch(e){}

  // --- Monkeypatch fetch/XHR to route cross-origin requests back to the proxy origin ---
  try {
    const _fetch = window.fetch.bind(window);
    window.fetch = function(input, init) {
      try {
        const u = new URL(input, location.href);
        if (u.origin !== location.origin) input = '/uv-proxy?url=' + encodeURIComponent(u.href);
      } catch(e){}
      return _fetch(input, init);
    };
  } catch(e){}

  try {
    const _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
      try {
        const u = new URL(url, location.href);
        if (u.origin !== location.origin) arguments[1] = '/uv-proxy?url=' + encodeURIComponent(u.href);
      } catch(e){}
      return _open.apply(this, arguments);
    };
  } catch(e){}
})();
</script>
`;

/**
 * Middleware factory.
 * Usage: app.use(securityProxy({ proxyPrefix: '/uv-proxy' }))
 * - The UV engine typically mounts its proxy handler on the root — to avoid collisions we can use '/uv-proxy' internal path,
 *   and have the middleware translate outgoing fetch/XHR to that path, or you can set it to '/' depending on UV config.
 */
export default function securityProxy(opts = {}) {
  const proxyPrefix = opts.proxyPrefix || "/proxy"; // match UV mount if needed

  return async function (req, res, next) {
    // Create per-session cookie jar if missing (requires express-session)
    try {
      if (req.session) {
        if (!req.session._cookieJar) {
          const jar = new CookieJar();
          req.session._cookieJar = JSON.stringify(jar.toJSON());
        }
        // restore jar into request for use by UV or other fetch code
        req._cookieJar = CookieJar.fromJSON(JSON.parse(req.session._cookieJar));
      }
    } catch (e) {
      console.error("cookie-jar init error", e && e.message);
    }

    // Strip incoming identifying headers so upstream doesn't see client UA/IP
    delete req.headers["user-agent"];
    delete req.headers["referer"];
    delete req.headers["x-forwarded-for"];
    delete req.headers["forwarded"];

    // Hook res.write/res.end to intercept HTML responses and inject the snippet
    const _write = res.write;
    const _end = res.end;
    const chunks = [];

    res.write = function (chunk, ...args) {
      try {
        if (chunk) chunks.push(Buffer.from(chunk));
        return true;
      } catch (e) {
        return _write.apply(res, [chunk, ...args]);
      }
    };

    res.end = function (chunk, ...args) {
      try {
        if (chunk) chunks.push(Buffer.from(chunk));
        const body = Buffer.concat(chunks);
        let contentType = res.getHeader("content-type") || "";

        // Remove upstream CSP to ensure injected inline scripts run
        res.removeHeader && res.removeHeader("content-security-policy");
        res.removeHeader && res.removeHeader("content-security-policy-report-only");

        // Always strip Set-Cookie before sending to client (cookie isolation)
        res.removeHeader && res.removeHeader("set-cookie");

        // If HTML, inject snippet and write safe headers
        if (/text\\/html/i.test(contentType)) {
          let html = body.toString("utf8");
          // inject into head (as early as possible)
          html = html.replace(/<head(\\s[^>]*)?>/i, (m) => `${m}\\n${INJECT_SNIPPET}\\n`);
          // set safe headers
          res.setHeader("permissions-policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()");
          res.setHeader("referrer-policy", "no-referrer");
          res.setHeader("cache-control", "no-store");
          _end.apply(res, [Buffer.from(html, "utf8"), ...args]);
        } else {
          // non-html: just forward bytes (but we already removed set-cookie/csp)
          _end.apply(res, [body, ...args]);
        }
      } catch (e) {
        console.error("security proxy end error", e && e.message);
        return _end.apply(res, [chunk, ...args]);
      }
    };

    // After response is finished, persist cookie jar back to session
    res.on("finish", async () => {
      try {
        if (req._cookieJar && req.session) {
          req.session._cookieJar = JSON.stringify(req._cookieJar.toJSON());
          // optionally save session (depends on session store)
          if (req.session.save) await once(req.session, "save");
        }
      } catch (e) {
        console.error("persist jar error", e && e.message);
      }
    });

    return next();
  };
}

