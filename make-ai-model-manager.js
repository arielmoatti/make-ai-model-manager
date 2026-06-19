/**
 * Make AI Model Manager — Local web app for managing AI model versions across Make.com scenarios.
 *
 * Usage:
 *   node make-ai-model-manager.js            -- starts on http://localhost:3000
 *   node make-ai-model-manager.js --port=8080 -- custom port
 *
 * Token:  entered once in the UI, saved to ./make-ai-model-manager.secret.json (gitignored)
 * Config: rules + last-used org, stored in ./make-ai-model-manager.json
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const CONFIG_PATH = path.join(__dirname, 'make-ai-model-manager.json');
const SECRET_PATH = path.join(__dirname, 'make-ai-model-manager.secret.json');
const PORT = parseInt((process.argv.find(a => a.startsWith('--port=')) || '').split('=')[1]) || 3000;

// ─── Config I/O ──────────────────────────────────────────────────────────────

// Token storage: plain JSON file next to the script (same folder as config).
// Gitignored. Threat model: localhost dev utility — if someone has your disk,
// any secret-at-rest scheme short of proper keychain integration is equivalent.
function loadToken() {
  try {
    const s = JSON.parse(fs.readFileSync(SECRET_PATH, 'utf-8'));
    return typeof s.token === 'string' && s.token.trim() ? s.token.trim() : null;
  } catch { return null; }
}

function saveToken(token) {
  fs.writeFileSync(SECRET_PATH, JSON.stringify({ token, savedAt: new Date().toISOString() }, null, 2), 'utf-8');
  try { fs.chmodSync(SECRET_PATH, 0o600); } catch {} // best-effort — no-op on Windows
}

function clearToken() {
  try { fs.unlinkSync(SECRET_PATH); } catch {}
}

function loadConfig() {
  let cfg;
  try {
    cfg = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  } catch {
    cfg = { make: {}, rules: [] };
  }
  cfg.make = cfg.make || {};
  const token = loadToken();
  if (token) cfg.make.token = token;
  return cfg;
}

function saveConfig(cfg) {
  // Never persist token to disk — env is the source of truth.
  const toSave = JSON.parse(JSON.stringify(cfg));
  if (toSave.make) delete toSave.make.token;
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(toSave, null, 2), 'utf-8');
}

// ─── Generic HTTPS client ────────────────────────────────────────────────────

function httpsRequest(method, hostname, reqPath, headers, body = null) {
  return new Promise((resolve, reject) => {
    const opts = { hostname, path: reqPath, method, headers };
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const out = { status: res.statusCode, headers: res.headers };
        try { out.body = JSON.parse(data); } catch { out.body = data; }
        resolve(out);
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// ─── Make API client ─────────────────────────────────────────────────────────

function makeApi(method, zone, token, apiPath, body = null) {
  return httpsRequest(method, `${zone}.make.com`, `/api/v2${apiPath}`, {
    'Authorization': `Token ${token}`,
    'Content-Type': 'application/json',
  }, body);
}

// ─── Scanning engine ─────────────────────────────────────────────────────────

function findMatchingModules(blueprint, rules) {
  const toUpdate = [];
  const skipped = [];
  const orphans = [];
  const currentTarget = [];
  const seen = new Set();

  const orphanIds = new Set();
  const designerOrphans = blueprint?.metadata?.designer?.orphans;
  if (Array.isArray(designerOrphans)) {
    (function collectIds(obj) {
      if (Array.isArray(obj)) obj.forEach(i => collectIds(i));
      else if (obj && typeof obj === 'object') {
        if (obj.id !== undefined && obj.module !== undefined) orphanIds.add(obj.id);
        for (const k of Object.keys(obj)) collectIds(obj[k]);
      }
    })(designerOrphans);
  }

  (function deepScan(obj) {
    if (Array.isArray(obj)) {
      for (const item of obj) deepScan(item);
    } else if (obj && typeof obj === 'object') {
      if (obj.id !== undefined && obj.module !== undefined && !seen.has(obj.id)) {
        seen.add(obj.id);
        const model = obj.mapper?.model || obj.parameters?.model;
        if (model) {
          const ml = model.toLowerCase();
          const isOrphan = orphanIds.has(obj.id);
          let matched = false;
          for (const rule of rules) {
            const matchesRule = rule.from.some(f => {
              try { return new RegExp(f, 'i').test(model); }
              catch { return ml.includes(String(f).toLowerCase()); }
            });
            if (matchesRule) {
              const entry = {
                moduleId: obj.id,
                moduleName: obj.module || '',
                model,
                location: obj.mapper?.model ? 'mapper' : 'parameters',
                targetModel: rule.to,
                targetLabel: rule.toLabel,
              };
              if (model.toLowerCase() === rule.to.toLowerCase()) {
                currentTarget.push(entry);
              } else if (isOrphan) {
                orphans.push(entry);
              } else {
                toUpdate.push(entry);
              }
              matched = true;
              break;
            }
          }
          if (!matched && (ml.includes('claude') || ml.includes('gemini'))) {
            skipped.push({ moduleId: obj.id, moduleName: obj.module || '', model, location: obj.mapper?.model ? 'mapper' : 'parameters' });
          }
        }
      }
      for (const k of Object.keys(obj)) deepScan(obj[k]);
    }
  })(blueprint);

  return { toUpdate, skipped, orphans, currentTarget };
}

// ─── Patching engine ─────────────────────────────────────────────────────────

function patchBlueprint(blueprint, updates) {
  const targetMap = new Map(updates.map(u => [u.moduleId, u]));
  const patched = new Set();

  (function deepPatch(obj) {
    if (Array.isArray(obj)) {
      for (const item of obj) deepPatch(item);
    } else if (obj && typeof obj === 'object') {
      if (obj.id !== undefined && obj.module !== undefined && !patched.has(obj.id)) {
        const target = targetMap.get(obj.id);
        if (target) {
          patched.add(obj.id);
          if (obj.mapper?.model) obj.mapper.model = target.targetModel;
          else if (obj.parameters?.model) obj.parameters.model = target.targetModel;
          if (obj.metadata?.restore?.expect?.model) {
            obj.metadata.restore.expect.model = { mode: 'chose', label: target.targetLabel };
          }
        }
      }
      for (const k of Object.keys(obj)) deepPatch(obj[k]);
    }
  })(blueprint);

  return blueprint;
}

// ─── Route handlers ──────────────────────────────────────────────────────────

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      try { resolve(JSON.parse(data)); }
      catch { resolve(data); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

// Validate a token by trying each zone's /users/me until one returns 200.
async function validateToken(token) {
  const zones = ['eu1', 'eu2', 'us1', 'us2'];
  for (const z of zones) {
    const r = await makeApi('GET', z, token, '/users/me');
    if (r.status === 200) {
      const user = r.body.authUser || r.body;
      return { ok: true, authZone: z, user: { name: user.name, email: user.email } };
    }
  }
  return { ok: false };
}

async function handleSetToken(body, res) {
  const raw = typeof body?.token === 'string' ? body.token.trim() : '';
  if (!raw) return sendJson(res, 400, { error: 'Token is empty.' });
  const v = await validateToken(raw);
  if (!v.ok) return sendJson(res, 401, { error: 'Invalid or rejected token (tried all zones).' });
  saveToken(raw);
  sendJson(res, 200, { ok: true, authZone: v.authZone, user: v.user });
}

async function handleClearToken(res) {
  clearToken();
  sendJson(res, 200, { ok: true });
}

async function handleConnect(res) {
  const token = loadToken();
  if (!token) return sendJson(res, 400, { error: 'No API token stored.', needsToken: true });

  try {
    const zones = ['eu1', 'eu2', 'us1', 'us2'];
    let authZone = null;
    let userRes = null;
    for (const z of zones) {
      const r = await makeApi('GET', z, token, '/users/me');
      if (r.status === 200) { authZone = z; userRes = r; break; }
    }
    if (!authZone || !userRes) return sendJson(res, 401, { error: 'Invalid API token (tried all zones)' });

    const user = userRes.body.authUser || userRes.body;

    const orgRes = await makeApi('GET', authZone, token, '/organizations');
    const orgs = orgRes.body?.organizations || [];

    const orgList = [];
    for (const o of orgs) {
      const orgZone = (o.zone || '').replace('.make.com', '') || authZone;
      const teamsRes = await makeApi('GET', orgZone, token, `/teams?organizationId=${o.id}`);
      const teams = (teamsRes.body?.teams || []).map(t => ({ id: t.id, name: t.name }));
      orgList.push({ id: o.id, name: o.name || '', zone: orgZone, teams });
    }

    const cfg = loadConfig();
    cfg.make = { ...cfg.make, authZone };
    saveConfig(cfg);

    sendJson(res, 200, {
      user: { name: user.name, email: user.email },
      authZone,
      organizations: orgList,
    });
  } catch (e) {
    sendJson(res, 500, { error: e.message });
  }
}

async function handleSelectOrg(body, res) {
  const { orgId, orgName, zone, teamId } = body || {};
  if (!orgId || !zone || !teamId) return sendJson(res, 400, { error: 'Missing orgId, zone, or teamId' });

  const cfg = loadConfig();
  cfg.make = { ...cfg.make, orgId: orgId.toString(), orgName: orgName || '', zone, teamId: teamId.toString() };
  saveConfig(cfg);

  sendJson(res, 200, { ok: true, orgId, orgName, zone, teamId });
}

async function handleScan(params, res) {
  const cfg = loadConfig();
  const { token, zone, teamId } = cfg.make || {};

  // SSE setup
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  try { res.socket?.setNoDelay(true); } catch {}
  const send = (event, data) => res.write('event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n');

  if (!token) { send('done', { error: 'No API token stored. Enter one in Step 1.' }); return res.end(); }
  if (!zone) { send('done', { error: 'No organization selected.' }); return res.end(); }

  let rules;
  const rulesParam = params.get('rules');
  if (rulesParam) {
    try { rules = JSON.parse(decodeURIComponent(rulesParam)); } catch { rules = cfg.rules || []; }
  } else {
    rules = cfg.rules || [];
  }
  if (!rules.length) { send('done', { error: 'No replacement rules configured.' }); return res.end(); }

  try {
    const activeOnly = !params.get('all');
    // Retry the listing too — on cold starts Make can 429 the very first call
    const listDelays = [0, 2000, 6000, 15000];
    let listRes;
    for (const d of listDelays) {
      if (d) {
        send('progress', { done: 0, total: 0, name: 'rate limited \u2014 waiting ' + (d/1000) + 's\u2026' });
        await new Promise(r => setTimeout(r, d));
      }
      listRes = await makeApi('GET', zone, token, `/scenarios?teamId=${teamId}` + (activeOnly ? '&isActive=true' : ''));
      if (listRes.status === 200) break;
      if (listRes.status !== 429 && listRes.status < 500) break;
    }
    if (listRes.status !== 200) {
      const hint = listRes.status === 429 ? ' — Make rate limit hit; wait ~60s and try again.' : '';
      send('done', { error: 'Failed to list scenarios (HTTP ' + listRes.status + ')' + hint, detail: listRes.body });
      return res.end();
    }

    const scenarios = listRes.body.scenarios || [];
    const results = [];
    send('progress', { done: 0, total: scenarios.length, name: '' });

    for (let i = 0; i < scenarios.length; i++) {
      const s = scenarios[i];
      send('progress', { done: i, total: scenarios.length, name: s.name });

      // Fetch blueprint with retry on 429/5xx (Make throttles under load)
      // Honor Retry-After header when present; otherwise exponential backoff.
      let bpRes;
      const delays = [0, 1500, 4000, 10000, 25000];
      for (let attempt = 0; attempt < delays.length; attempt++) {
        let wait = delays[attempt];
        if (attempt > 0 && bpRes?.status === 429) {
          const ra = parseInt(bpRes.headers?.['retry-after'] || '', 10);
          if (ra > 0) wait = Math.max(wait, ra * 1000);
          send('progress', { done: i, total: scenarios.length, name: s.name + ' \u2014 429, waiting ' + Math.round(wait/1000) + 's\u2026' });
        }
        if (wait) await new Promise(r => setTimeout(r, wait));
        bpRes = await makeApi('GET', zone, token, `/scenarios/${s.id}/blueprint`);
        if (bpRes.status === 200) break;
        if (bpRes.status !== 429 && bpRes.status < 500) break;
      }
      if (!bpRes || bpRes.status !== 200) {
        const body = typeof bpRes?.body === 'string' ? bpRes.body : JSON.stringify(bpRes?.body || {});
        results.push({ name: s.name, id: s.id, status: 'error', detail: `HTTP ${bpRes?.status || '?'} — ${body.slice(0, 120)}` });
        continue;
      }

      // Pace between scenarios to stay under Make's per-org rate limit
      await new Promise(r => setTimeout(r, 400));

      const bpRaw = bpRes.body.response?.blueprint;
      if (!bpRaw) { results.push({ name: s.name, id: s.id, status: 'no-ai' }); continue; }

      let blueprint;
      try { blueprint = typeof bpRaw === 'string' ? JSON.parse(bpRaw) : bpRaw; }
      catch { results.push({ name: s.name, id: s.id, status: 'error', detail: 'Could not parse blueprint' }); continue; }

      const { toUpdate, skipped, orphans, currentTarget } = findMatchingModules(blueprint, rules);
      const hasAI = toUpdate.length + skipped.length + orphans.length + currentTarget.length > 0;

      if (!hasAI) {
        results.push({ name: s.name, id: s.id, status: 'no-ai' });
        continue;
      }

      const status = toUpdate.length > 0 ? 'update' : (currentTarget.length > 0 && skipped.length === 0 && orphans.length === 0) ? 'current' : 'info';
      results.push({ name: s.name, id: s.id, status, toUpdate, skipped, orphans, currentTarget });
    }

    send('progress', { done: scenarios.length, total: scenarios.length, name: '' });
    send('done', { total: scenarios.length, results });
    res.end();
  } catch (e) {
    send('done', { error: e.message });
    res.end();
  }
}

async function handleApply(body, res) {
  const cfg = loadConfig();
  const { token, zone } = cfg.make || {};
  if (!token) return sendJson(res, 400, { error: 'No API token stored. Enter one in Step 1.' });
  if (!zone) return sendJson(res, 400, { error: 'No organization selected.' });

  const selections = body?.selections || [];
  if (!selections.length) return sendJson(res, 400, { error: 'Nothing selected.' });

  const results = [];

  const retryingCall = async (method, path, body) => {
    const delays = [0, 1500, 4000, 10000, 25000];
    let r;
    for (let attempt = 0; attempt < delays.length; attempt++) {
      let wait = delays[attempt];
      if (attempt > 0 && r?.status === 429) {
        const ra = parseInt(r.headers?.['retry-after'] || '', 10);
        if (ra > 0) wait = Math.max(wait, ra * 1000);
      }
      if (wait) await new Promise(r => setTimeout(r, wait));
      r = await makeApi(method, zone, token, path, body);
      if (r.status === 200) break;
      if (r.status !== 429 && r.status < 500) break;
    }
    return r;
  };

  for (const sel of selections) {
    const { scenarioId, modules } = sel;
    try {
      const bpRes = await retryingCall('GET', `/scenarios/${scenarioId}/blueprint`);
      if (bpRes.status !== 200) {
        const msg = typeof bpRes.body === 'object' ? (bpRes.body?.message || bpRes.body?.detail || JSON.stringify(bpRes.body)) : String(bpRes.body);
        results.push({ scenarioId, status: 'error', detail: 'Could not fetch blueprint (HTTP ' + bpRes.status + '): ' + msg });
        continue;
      }

      await new Promise(r => setTimeout(r, 400));

      const bpRaw = bpRes.body.response?.blueprint;
      let blueprint;
      try { blueprint = typeof bpRaw === 'string' ? JSON.parse(bpRaw) : bpRaw; }
      catch { results.push({ scenarioId, status: 'error', detail: 'Could not parse blueprint' }); continue; }

      const patched = patchBlueprint(blueprint, modules);
      const patchRes = await retryingCall('PATCH', `/scenarios/${scenarioId}`, { blueprint: JSON.stringify(patched) });

      if (patchRes.status === 200) {
        results.push({ scenarioId, status: 'success', modulesPatched: modules.length });
      } else {
        const msg = typeof patchRes.body === 'object' ? (patchRes.body?.message || patchRes.body?.detail || JSON.stringify(patchRes.body)) : String(patchRes.body);
        results.push({ scenarioId, status: 'failed', detail: 'HTTP ' + patchRes.status + ': ' + msg });
      }
    } catch (e) {
      results.push({ scenarioId, status: 'error', detail: e.message });
    }
  }

  sendJson(res, 200, { results });
}

// ─── Embedded HTML ───────────────────────────────────────────────────────────

const HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Make Model Manager</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --surface2: #242836;
    --border: #2e3348; --text: #e4e6f0; --text2: #8b90a5;
    --accent: #6c7ee1; --accent-hover: #8190f0;
    --green: #4ade80; --red: #f87171; --orange: #fbbf24; --ghost: #6366f1;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }
  h1 { font-size: 1.5rem; margin-bottom: 4px; }
  .subtitle { color: var(--text2); font-size: 0.875rem; margin-bottom: 32px; }

  .step { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 20px; }
  .step-header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
  .step-num { background: var(--accent); color: #fff; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: 700; flex-shrink: 0; }
  .step-title { font-size: 1.1rem; font-weight: 600; }
  .step-badge { margin-left: auto; font-size: 0.95rem; padding: 6px 16px; border-radius: 999px; font-weight: 700; letter-spacing: 0.2px; }
  .badge-ok { background: rgba(74,222,128,0.15); color: var(--green); }
  .badge-warn { background: rgba(251,191,36,0.15); color: var(--orange); }

  .row { display: flex; gap: 12px; margin-bottom: 12px; align-items: flex-end; flex-wrap: wrap; }
  label { display: block; font-size: 0.8rem; color: var(--text2); margin-bottom: 4px; }
  input, select { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; color: var(--text); font-size: 0.875rem; outline: none; }
  input:focus, select:focus { border-color: var(--accent); }
  input.wide { flex: 1; min-width: 200px; }
  select { cursor: pointer; }
  button { background: var(--accent); color: #fff; border: none; border-radius: 8px; padding: 8px 20px; font-size: 0.875rem; font-weight: 600; cursor: pointer; transition: background .15s; }
  button:hover { background: var(--accent-hover); }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  button.secondary { background: var(--surface2); border: 1px solid var(--border); }
  button.secondary:hover { background: var(--border); }
  button.danger { background: var(--red); }
  button.danger:hover { background: #ef4444; }
  .info { color: var(--text2); font-size: 0.8rem; margin-top: 8px; }
  .info.success { color: var(--green); }
  .info.error { color: var(--red); }

  .token-note { background: var(--surface2); border-radius: 8px; padding: 10px 14px; font-size: 0.8rem; color: var(--text2); display: flex; align-items: center; gap: 8px; }
  .token-note code { background: var(--bg); padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; color: var(--text); }

  .rules-section { margin-top: 16px; }
  .rule-row { display: flex; gap: 8px; align-items: flex-end; margin-bottom: 8px; flex-wrap: wrap; }
  .rule-row input { font-size: 0.8rem; padding: 6px 10px; }
  .rule-row .from { flex: 2; min-width: 180px; }
  .rule-row .to { flex: 1; min-width: 140px; }
  .rule-row .lbl { flex: 1; min-width: 120px; }
  .rule-row button { padding: 6px 12px; font-size: 0.75rem; }

  .results-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; margin-top: 16px; }
  .results-table th { text-align: left; padding: 8px 10px; border-bottom: 2px solid var(--border); color: var(--text2); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
  .results-table td { padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  .results-table tr:hover td { background: var(--surface2); }
  .results-table .scenario-name { font-weight: 600; }
  .results-table tr.scenario-header td { background: var(--surface2); border-top: 2px solid var(--accent); padding: 12px 10px 10px 10px; font-size: 0.9rem; }
  .results-table tr.scenario-header:hover td { background: var(--surface2); }
  .results-table .sh-name { font-weight: 700; color: var(--text); }
  .results-table .sh-id { font-weight: 400; color: var(--text2); font-size: 0.8rem; margin-left: 6px; }
  .results-table tr.mod-row td { background: transparent; }
  .mod-update { color: var(--red); }
  .mod-orphan { color: var(--ghost); opacity: 0.6; }
  .mod-current { color: var(--green); opacity: 0.75; }
  .mod-ok { color: var(--orange); }
  .check-col { width: 30px; text-align: center; }
  input[type="checkbox"] { accent-color: var(--accent); cursor: pointer; width: 16px; height: 16px; }

  .summary { background: var(--surface2); border-radius: 8px; padding: 16px; margin-top: 16px; display: flex; gap: 24px; flex-wrap: wrap; }
  .summary-item { text-align: center; }
  .summary-num { font-size: 1.5rem; font-weight: 700; }
  .summary-label { font-size: 0.75rem; color: var(--text2); }

  .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .6s linear infinite; vertical-align: middle; margin-right: 6px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="container">
  <h1>Make Model Manager</h1>
  <p class="subtitle">Scan and update AI model versions across all your Make.com scenarios</p>

  <!-- STEP 1: Connect -->
  <div class="step" id="step-connect">
    <div class="step-header">
      <span class="step-num">1</span>
      <span class="step-title">Connect to Make.com</span>
      <span class="step-badge hidden" id="connect-badge"></span>
    </div>
    <div id="token-panel"></div>
    <div class="row" style="margin-top:12px;" id="connect-row">
      <button id="btn-connect" onclick="doConnect()">Reconnect</button>
      <button id="btn-disconnect-token" class="secondary" onclick="disconnectToken()" style="display:none;">Disconnect key</button>
    </div>
    <div class="info" id="connect-info"></div>
    <div id="org-selector" class="hidden" style="margin-top:16px;">
      <label style="font-weight:600;color:var(--text);margin-bottom:6px;display:block;">Select Organization</label>
      <div style="display:flex;gap:8px;flex-wrap:wrap;" id="org-buttons"></div>
    </div>
    <div id="connect-details" class="hidden" style="margin-top:16px;background:var(--surface2);border-radius:8px;padding:16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;">
    </div>
  </div>

  <!-- STEP 2: Model Targets -->
  <div class="step" id="step-rules">
    <div class="step-header">
      <span class="step-num">2</span>
      <span class="step-title">Model Replacement Rules</span>
    </div>

    <p style="font-size:0.8rem;color:var(--text2);margin-bottom:12px;">Each rule matches old model substrings and replaces them with a target model. Pick a preset or create your own.</p>

    <div style="margin-bottom:16px;">
      <label style="margin-bottom:6px;font-weight:600;color:var(--text)">Quick Add Presets</label>
      <div style="display:flex;gap:8px;flex-wrap:wrap;" id="presets-row"></div>
    </div>

    <div class="rules-section">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <label style="margin:0;font-size:0.9rem;font-weight:600;color:var(--text)">Active Rules</label>
        <button class="secondary" onclick="addRule()" style="font-size:0.75rem;padding:4px 12px;">+ Custom Rule</button>
      </div>
      <div style="display:flex;gap:8px;margin-bottom:6px;font-size:0.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px;">
        <span style="flex:2;min-width:180px;padding-left:4px;">Match (comma-separated substrings)</span>
        <span style="flex:1;min-width:140px;">Target model ID</span>
        <span style="flex:1;min-width:120px;">UI label (for Make dropdown)</span>
        <span style="width:60px;"></span>
      </div>
      <div id="rules-list"></div>
    </div>
    <button onclick="saveRules()" style="margin-top:12px;">Save Rules</button>
    <div class="info" id="rules-info"></div>
  </div>

  <!-- STEP 3: Scan -->
  <div class="step" id="step-scan">
    <div class="step-header">
      <span class="step-num">3</span>
      <span class="step-title">Scan Scenarios</span>
      <span class="step-badge hidden" id="scan-badge"></span>
    </div>
    <div class="row" style="align-items:center;">
      <button onclick="doScan()" id="btn-scan">Scan Scenarios</button>
      <label style="display:flex;align-items:center;gap:6px;margin:0;cursor:pointer;font-size:0.8rem;"><input type="checkbox" id="chk-inactive" style="width:14px;height:14px;"> Include inactive scenarios</label>
    </div>
    <div class="info" id="scan-info"></div>
    <div id="scan-summary" class="summary hidden"></div>
    <div id="scan-results"></div>
  </div>

  <!-- STEP 4: Apply -->
  <div class="step" id="step-apply">
    <div class="step-header">
      <span class="step-num">4</span>
      <span class="step-title">Apply Changes</span>
    </div>
    <div class="row">
      <button class="danger" onclick="doApply()" id="btn-apply" disabled>Apply Selected Changes</button>
      <button class="secondary" onclick="selectAll(true)">Select All</button>
      <button class="secondary" onclick="selectAll(false)">Deselect All</button>
    </div>
    <div class="info" id="apply-info"></div>
    <div id="apply-results"></div>
  </div>
</div>

<script>
let scanData = null;
let allOrgs = [];
let makeZone = 'eu2';
let makeTeamId = null;

function scenarioUrl(id) {
  if (!makeTeamId) return null;
  return 'https://' + makeZone + '.make.com/' + makeTeamId + '/scenarios/' + id + '/edit';
}

function scenarioLink(name, id) {
  const url = scenarioUrl(id);
  const inner = '<span class="sh-name">' + esc(name) + '</span> <span class="sh-id">#' + id + '</span>';
  if (!url) return inner;
  return '<a href="' + url + '" target="_blank" rel="noopener" style="color:inherit;text-decoration:none;cursor:pointer;">' + inner + '</a>';
}

const PRESETS = [
  { label: 'All Opus -> 4.8', from: ['^claude-opus'], to: 'claude-opus-4-8', toLabel: 'Claude Opus 4.8' },
  { label: 'All Sonnet -> 4.6', from: ['^claude-sonnet', '^claude-3-5-sonnet'], to: 'claude-sonnet-4-6', toLabel: 'Claude Sonnet 4.6' },
  { label: 'All Haiku -> 4.5', from: ['^claude-haiku', '^claude-3-haiku', '^claude-3-5-haiku'], to: 'claude-haiku-4-5-20251001', toLabel: 'Claude Haiku 4.5' },
  { label: 'All Gemini Pro -> latest', from: ['^gemini-([0-9.]+-)?pro(?!-image)'], to: 'gemini-pro-latest', toLabel: 'Gemini Pro Latest' },
  { label: 'All Gemini Flash -> latest', from: ['^gemini-([0-9.]+-)?flash(?!-lite)(?!-image)'], to: 'gemini-flash-latest', toLabel: 'Gemini Flash Latest' },
];

(async function init() {
  renderPresets();
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();
    if (cfg.make?.zone) makeZone = cfg.make.zone;
    if (cfg.make?.teamId) makeTeamId = cfg.make.teamId;
    if (cfg.rules?.length) renderRules(cfg.rules);
    else renderRules([]);
    renderTokenPanel(cfg.hasToken);
    if (cfg.hasToken) doConnect();
  } catch { renderRules([]); renderTokenPanel(false); }
})();

function renderTokenPanel(hasToken) {
  const panel = document.getElementById('token-panel');
  const btnConnect = document.getElementById('btn-connect');
  const btnDisconnect = document.getElementById('btn-disconnect-token');
  if (hasToken) {
    panel.innerHTML =
      '<div class="token-note">' +
        '<span style="color:var(--green);font-weight:600;">\u2713 API key stored.</span>' +
        '<span style="color:var(--text2);">Saved in <code>make-ai-model-manager.secret.json</code> next to the script.</span>' +
      '</div>';
    btnConnect.style.display = '';
    btnDisconnect.style.display = '';
  } else {
    panel.innerHTML =
      '<div class="token-note" style="flex-direction:column;align-items:stretch;gap:10px;">' +
        '<div style="display:flex;align-items:center;gap:10px;">' +
          '<span>No API key stored.</span>' +
          '<button id="btn-enter-key" onclick="showTokenInput()">Enter API key</button>' +
        '</div>' +
        '<div id="token-input-row" style="display:none;align-items:center;gap:8px;">' +
          '<input id="token-input" type="text" inputmode="text" placeholder="Paste Make.com API token" style="flex:1;font-size:0.85rem;padding:7px 10px;-webkit-text-security:disc;text-security:disc;" autocomplete="one-time-code" autocorrect="off" autocapitalize="off" spellcheck="false" name="make-api-token" data-lpignore="true" data-1p-ignore="true" data-bwignore="true">' +
          '<button onclick="saveTokenFromInput()">Save</button>' +
          '<button class="secondary" onclick="hideTokenInput()">Cancel</button>' +
        '</div>' +
        '<div id="token-status" class="info" style="margin:0;"></div>' +
      '</div>';
    btnConnect.style.display = 'none';
    btnDisconnect.style.display = 'none';
  }
}

function showTokenInput() {
  document.getElementById('token-input-row').style.display = 'flex';
  document.getElementById('btn-enter-key').style.display = 'none';
  const input = document.getElementById('token-input');
  input.focus();
  input.addEventListener('keydown', e => { if (e.key === 'Enter') saveTokenFromInput(); });
}

function hideTokenInput() {
  document.getElementById('token-input-row').style.display = 'none';
  const b = document.getElementById('btn-enter-key');
  if (b) b.style.display = '';
  document.getElementById('token-status').innerHTML = '';
  document.getElementById('token-status').className = 'info';
}

async function saveTokenFromInput() {
  const input = document.getElementById('token-input');
  const token = input.value.trim();
  const status = document.getElementById('token-status');
  if (!token) { status.innerHTML = 'Please paste a token first.'; status.className = 'info error'; return; }
  status.innerHTML = '<span class="spinner"></span> Validating\u2026';
  status.className = 'info';
  try {
    const res = await fetch('/api/set-token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Validation failed');
    status.innerHTML = '\u2713 API key loaded successfully.';
    status.className = 'info success';
    input.value = '';
    setTimeout(() => { renderTokenPanel(true); doConnect(); }, 600);
  } catch (e) {
    status.innerHTML = 'Failed: ' + e.message;
    status.className = 'info error';
  }
}

async function disconnectToken() {
  if (!confirm('Remove the stored API key? You will need to paste it again to reconnect.')) return;
  await fetch('/api/clear-token', { method: 'POST' });
  document.getElementById('connect-badge').classList.add('hidden');
  document.getElementById('connect-details').classList.add('hidden');
  document.getElementById('org-selector').classList.add('hidden');
  setInfo('connect-info', '', '');
  allOrgs = [];
  renderTokenPanel(false);
}

function renderPresets() {
  const row = document.getElementById('presets-row');
  const activeTargets = new Set(
    Array.from(document.querySelectorAll('#rules-list .rule-row .to'))
      .map(i => i.value.trim())
      .filter(Boolean)
  );
  row.innerHTML = PRESETS.map((p, i) => {
    const used = activeTargets.has(p.to);
    const style = used
      ? 'font-size:0.75rem;padding:5px 14px;opacity:0.45;cursor:not-allowed;'
      : 'font-size:0.75rem;padding:5px 14px;';
    const title = used ? ' title="Already in your rules."' : '';
    const disabled = used ? ' disabled' : '';
    return '<button class="secondary"' + disabled + title + ' style="' + style + '" onclick="addPreset(' + i + ')">' +
      (used ? '\u2713 ' : '+ ') + esc(p.label) + '</button>';
  }).join('');
}

function addPreset(i) {
  const p = PRESETS[i];
  const existing = getRules();
  if (existing.some(r => r.to === p.to)) return setInfo('rules-info', 'Rule for ' + p.to + ' already exists.', 'error');
  appendRuleRow({ from: p.from, to: p.to, toLabel: p.toLabel });
  setInfo('rules-info', 'Added: ' + p.label, 'success');
}

async function doConnect() {
  setInfo('connect-info', '<span class="spinner"></span> Connecting (auto-detecting zone)...', '');
  document.getElementById('connect-details').classList.add('hidden');
  document.getElementById('org-selector').classList.add('hidden');
  try {
    const res = await fetch('/api/connect');
    const data = await res.json();
    if (!res.ok) return setInfo('connect-info', 'Error: ' + (data.error || 'Unknown'), 'error');

    allOrgs = data.organizations || [];
    setInfo('connect-info', '', '');

    if (allOrgs.length === 1) {
      await selectOrg(0);
    } else if (allOrgs.length > 1) {
      renderOrgSelector(data.user);
      const cfg = await (await fetch('/api/config')).json();
      const savedOrgId = cfg.make?.orgId;
      if (savedOrgId) {
        const idx = allOrgs.findIndex(o => o.id.toString() === savedOrgId.toString());
        if (idx >= 0) await selectOrg(idx);
      }
    }
  } catch (e) {
    setInfo('connect-info', 'Connection failed: ' + e.message, 'error');
  }
}

function renderOrgSelector(user) {
  const sel = document.getElementById('org-selector');
  sel.classList.remove('hidden');
  const btns = document.getElementById('org-buttons');
  btns.innerHTML = allOrgs.map((o, i) =>
    '<button class="secondary org-btn" data-idx="' + i + '" onclick="selectOrg(' + i + ')" style="font-size:0.8rem;padding:8px 16px;">' +
    esc(o.name) + ' <span style="color:var(--text2);font-size:0.7rem;">(' + esc(o.zone) + ')</span></button>'
  ).join('');
}

async function selectOrg(idx) {
  const o = allOrgs[idx];
  if (!o) return;

  document.querySelectorAll('.org-btn').forEach((b, i) => {
    const selected = i === idx;
    b.style.background = selected ? 'var(--accent)' : '';
    b.style.color = selected ? '#fff' : '';
    b.style.borderColor = selected ? 'var(--accent)' : '';
    const zoneSpan = b.querySelector('span');
    if (zoneSpan) zoneSpan.style.color = selected ? 'rgba(255,255,255,0.85)' : 'var(--text2)';
  });

  const team = o.teams[0] || {};
  await fetch('/api/select-org', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ orgId: o.id, orgName: o.name, zone: o.zone, teamId: team.id })
  });
  if (o.zone) makeZone = o.zone;
  if (team.id) makeTeamId = team.id;

  // Reset stale scan + apply state so prior org data doesn't leak across orgs
  scanData = null;
  const inactiveChk = document.getElementById('chk-inactive');
  if (inactiveChk) inactiveChk.checked = false;
  document.getElementById('scan-results').innerHTML = '';
  const sum = document.getElementById('scan-summary');
  sum.innerHTML = '';
  sum.style.display = '';
  sum.classList.add('hidden');
  document.getElementById('scan-badge').classList.add('hidden');
  setInfo('scan-info', '', '');
  document.getElementById('apply-results').innerHTML = '';
  setInfo('apply-info', '', '');
  document.getElementById('btn-apply').disabled = true;

  showBadge('connect-badge', o.name, 'ok');

  const det = document.getElementById('connect-details');
  det.classList.remove('hidden');
  det.innerHTML =
    detailCard('Organization', o.name + ' (#' + o.id + ')') +
    detailCard('Zone', o.zone) +
    detailCard('Team' + (o.teams.length > 1 ? 's' : ''), o.teams.map(t => t.name + ' (#' + t.id + ')').join(', '));
}

function detailCard(label, value) {
  return '<div><div style="font-size:0.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:2px;">' + esc(label) + '</div><div style="font-size:0.9rem;font-weight:600;">' + esc(value) + '</div></div>';
}

function appendRuleRow(r) {
  const el = document.getElementById('rules-list');
  const row = document.createElement('div');
  row.className = 'rule-row';
  row.innerHTML =
    '<input class="from" value="' + esc((r.from || []).join(', ')) + '" placeholder="e.g. claude-3-5-sonnet, claude-sonnet-4-5">' +
    '<input class="to" value="' + esc(r.to || '') + '" placeholder="e.g. claude-sonnet-4-6" oninput="renderPresets()">' +
    '<input class="lbl" value="' + esc(r.toLabel || '') + '" placeholder="e.g. Claude Sonnet 4.6">' +
    '<button class="secondary" onclick="removeRuleRow(this)">Remove</button>';
  el.appendChild(row);
  renderPresets();
}

function removeRuleRow(btn) {
  btn.parentElement.remove();
  renderPresets();
}

function renderRules(rules) {
  document.getElementById('rules-list').innerHTML = '';
  rules.forEach(r => appendRuleRow(r));
  renderPresets();
}

function addRule() {
  appendRuleRow({ from: [], to: '', toLabel: '' });
}

function getRules() {
  const rows = document.querySelectorAll('#rules-list .rule-row');
  const rules = [];
  rows.forEach(r => {
    const from = r.querySelector('.from').value.split(',').map(s => s.trim()).filter(Boolean);
    const to = r.querySelector('.to').value.trim();
    const toLabel = r.querySelector('.lbl').value.trim();
    if (from.length && to) rules.push({ from, to, toLabel: toLabel || to });
  });
  return rules;
}

async function saveRules() {
  const rules = getRules();
  const cfg = await (await fetch('/api/config')).json();
  cfg.rules = rules;
  await fetch('/api/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cfg) });
  setInfo('rules-info', 'Saved ' + rules.length + ' rule(s).', 'success');
}

async function doScan() {
  const rules = getRules();
  if (!rules.length) return setInfo('scan-info', 'Configure at least one rule in Step 2.', 'error');

  document.getElementById('btn-scan').disabled = true;
  setInfo('scan-info', '<span class="spinner"></span> Listing scenarios\u2026', '');
  document.getElementById('scan-results').innerHTML = '';
  document.getElementById('scan-summary').classList.add('hidden');
  // Reset the apply log so stale patch results don't linger across scans
  document.getElementById('apply-results').innerHTML = '';
  setInfo('apply-info', '', '');
  document.getElementById('btn-apply').disabled = true;

  const includeInactive = document.getElementById('chk-inactive').checked;
  const url = '/api/scan?rules=' + encodeURIComponent(JSON.stringify(rules)) + (includeInactive ? '&all=1' : '');

  const es = new EventSource(url);
  let finished = false;
  const finish = () => { finished = true; try { es.close(); } catch {} document.getElementById('btn-scan').disabled = false; };

  es.addEventListener('progress', (e) => {
    const p = JSON.parse(e.data);
    const pct = p.total ? Math.floor((p.done / p.total) * 100) : 0;
    const nameBit = p.name ? ' \u2014 <span style="color:var(--text2);">' + esc(p.name) + '</span>' : '';
    setInfo('scan-info', '<span class="spinner"></span> Scanning <b>' + p.done + ' / ' + p.total + '</b> (' + pct + '%)' + nameBit, '');
  });

  es.addEventListener('done', (e) => {
    const data = JSON.parse(e.data);
    if (data.error) {
      setInfo('scan-info', 'Scan failed: ' + data.error, 'error');
    } else {
      scanData = data;
      renderScanResults(data);
      setInfo('scan-info', '', '');
    }
    finish();
  });

  es.onerror = () => {
    if (finished) return;
    // If we already got results, don't overwrite — let EventSource reconnect silently; otherwise show error.
    setInfo('scan-info', 'Scan failed: connection error.', 'error');
    finish();
  };
}

function renderScanResults(data) {
  const results = data.results || [];
  let toUpdateCount = 0, orphanCount = 0, skippedCount = 0, currentCount = 0, noAiCount = 0;
  let scenariosToUpdateCount = 0, aiScenarioCount = 0;

  let html = '<table class="results-table"><thead><tr><th class="check-col"></th><th>Module</th><th>Current Model</th><th>Target</th><th>Status</th></tr></thead><tbody>';

  for (const r of results) {
    if (r.status === 'no-ai') { noAiCount++; continue; }

    if (r.status === 'error') {
      html += '<tr class="scenario-header"><td colspan="5">' + scenarioLink(r.name, r.id) + '</td></tr>';
      html += '<tr><td></td><td colspan="4" class="info error" style="padding-left:28px;">' + esc(r.detail || 'Error') + '</td></tr>';
      continue;
    }

    const mods = [
      ...(r.toUpdate || []).map(m => ({ m, kind: 'update' })),
      ...(r.orphans || []).map(m => ({ m, kind: 'orphan' })),
      ...(r.skipped || []).map(m => ({ m, kind: 'norule' })),
      ...(r.currentTarget || []).map(m => ({ m, kind: 'current' })),
    ];
    if (!mods.length) continue;

    aiScenarioCount++;
    html += '<tr class="scenario-header"><td colspan="5">' + scenarioLink(r.name, r.id) + '</td></tr>';
    if ((r.toUpdate || []).length > 0) scenariosToUpdateCount++;

    for (const { m, kind } of mods) {
      if (kind === 'update') toUpdateCount++;
      else if (kind === 'orphan') orphanCount++;
      else if (kind === 'norule') skippedCount++;
      else if (kind === 'current') currentCount++;

      const statusClass = kind === 'update' ? 'mod-update' : kind === 'orphan' ? 'mod-orphan' : kind === 'current' ? 'mod-current' : 'mod-ok';
      const statusText = kind === 'update' ? 'Needs update' : kind === 'orphan' ? 'Orphan (skip)' : kind === 'current' ? 'Already at latest' : 'No rule \u2014 verify';

      html += '<tr class="' + statusClass + ' mod-row">';
      html += '<td class="check-col">' + (kind === 'update' ? '<input type="checkbox" checked data-scenario="' + r.id + '" data-module="' + m.moduleId + '" data-target="' + esc(m.targetModel || '') + '" data-label="' + esc(m.targetLabel || '') + '">' : '') + '</td>';
      html += '<td style="padding-left:28px;">#' + m.moduleId + '</td>';
      html += '<td>' + esc(m.model) + '</td>';
      html += '<td>' + esc(m.targetModel || '\u2014') + '</td>';
      html += '<td>' + statusText + '</td>';
      html += '</tr>';
    }
  }
  html += '</tbody></table>';

  document.getElementById('scan-results').innerHTML = html;
  document.getElementById('btn-apply').disabled = toUpdateCount === 0;

  const sum = document.getElementById('scan-summary');
  sum.classList.remove('hidden');
  sum.style.display = 'block';
  const pill = (num, label, color, tooltip) =>
    '<div class="summary-item" title="' + esc(tooltip || '') + '"><div class="summary-num"' + (color ? ' style="color:' + color + '"' : '') + '>' + num + '</div><div class="summary-label">' + label + '</div></div>';

  let moduleStats = pill(toUpdateCount, 'Need updating', 'var(--red)', 'Modules that will be patched to the target model.');
  moduleStats += pill(currentCount, 'Up to date', 'var(--green)', 'Modules already on the rule target — no action needed.');
  if (orphanCount > 0) moduleStats += pill(orphanCount, 'Orphans', 'var(--ghost)', 'Modules in Make designer.orphans (detached from the active flow). Not patched.');
  if (skippedCount > 0) moduleStats += pill(skippedCount, 'No rule', 'var(--orange)', 'Modules with Claude/Gemini IDs that did not match any rule (e.g. Gemma, flash-lite, nano-banana). Verify manually.');

  let scenarioStats = pill(aiScenarioCount, 'Total scenarios', '', 'Scenarios that contain at least one AI module (Claude or Gemini). Scenarios with no AI modules are excluded from this count.');
  scenarioStats += pill(scenariosToUpdateCount, 'Need updating', scenariosToUpdateCount > 0 ? 'var(--red)' : '', 'Scenarios that contain at least one module needing an update.');

  sum.innerHTML =
    '<div style="display:flex;gap:24px;align-items:flex-end;flex-wrap:wrap;">' +
      '<div>' +
        '<div style="font-size:0.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Scenarios</div>' +
        '<div style="display:flex;gap:24px;flex-wrap:wrap;">' + scenarioStats + '</div>' +
      '</div>' +
      '<div style="width:2px;align-self:stretch;background:var(--text2);opacity:0.45;border-radius:2px;margin:0 12px;"></div>' +
      '<div style="flex:1;min-width:200px;">' +
        '<div style="font-size:0.7rem;color:var(--text2);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Modules</div>' +
        '<div style="display:flex;gap:24px;flex-wrap:wrap;">' + moduleStats + '</div>' +
      '</div>' +
    '</div>';

  showBadge('scan-badge', toUpdateCount + ' to update', toUpdateCount > 0 ? 'warn' : 'ok');
}

async function doApply() {
  const boxes = document.querySelectorAll('#scan-results input[type="checkbox"]:checked');
  if (!boxes.length) return setInfo('apply-info', 'Nothing selected.', 'error');

  const groups = {};
  boxes.forEach(b => {
    const sid = b.dataset.scenario;
    if (!groups[sid]) groups[sid] = [];
    groups[sid].push({ moduleId: parseInt(b.dataset.module), targetModel: b.dataset.target, targetLabel: b.dataset.label });
  });

  // Look up scenario names from the last scan for nicer display
  const nameById = {};
  for (const r of (scanData?.results || [])) nameById[r.id] = r.name;

  const selections = Object.entries(groups).map(([scenarioId, modules]) => ({
    scenarioId: parseInt(scenarioId),
    scenarioName: nameById[parseInt(scenarioId)] || '(scenario ' + scenarioId + ')',
    modules,
  }));

  document.getElementById('btn-apply').disabled = true;
  setInfo('apply-info', '', '');

  // Render empty log table
  document.getElementById('apply-results').innerHTML =
    '<table class="results-table" id="apply-log-table">' +
    '<thead><tr><th>Scenario</th><th style="width:110px;">Modules</th><th style="width:180px;">Status</th></tr></thead>' +
    '<tbody id="apply-log-body"></tbody></table>';
  const body = document.getElementById('apply-log-body');

  let ok = 0, fail = 0;

  for (const sel of selections) {
    // Insert "patching..." row
    const rowId = 'apply-row-' + sel.scenarioId;
    body.insertAdjacentHTML('beforeend',
      '<tr class="scenario-header" id="' + rowId + '">' +
        '<td>' + scenarioLink(sel.scenarioName, sel.scenarioId) + '</td>' +
        '<td>' + sel.modules.length + '</td>' +
        '<td class="apply-status"><span class="spinner"></span> patching\u2026</td>' +
      '</tr>'
    );
    // Scroll into view
    document.getElementById(rowId).scrollIntoView({ block: 'nearest', behavior: 'smooth' });

    try {
      const res = await fetch('/api/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selections: [{ scenarioId: sel.scenarioId, modules: sel.modules }] }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'request failed');
      const r = (data.results || [])[0] || {};
      const statusCell = document.querySelector('#' + rowId + ' .apply-status');
      if (r.status === 'success') {
        ok++;
        statusCell.innerHTML = '<span style="color:var(--green);font-weight:600;">\u2714 success</span>';
      } else {
        fail++;
        statusCell.innerHTML = '<span style="color:var(--red);font-weight:600;">\u2716 ' + esc(r.status || 'failed') + '</span>' +
          (r.detail ? '<div style="font-size:0.7rem;color:var(--text2);margin-top:2px;">' + esc(typeof r.detail === 'string' ? r.detail : JSON.stringify(r.detail)) + '</div>' : '');
      }
    } catch (e) {
      fail++;
      const statusCell = document.querySelector('#' + rowId + ' .apply-status');
      if (statusCell) statusCell.innerHTML = '<span style="color:var(--red);font-weight:600;">\u2716 error</span><div style="font-size:0.7rem;color:var(--text2);margin-top:2px;">' + esc(e.message) + '</div>';
    }
  }

  // Summary row at bottom
  const total = selections.length;
  body.insertAdjacentHTML('beforeend',
    '<tr><td colspan="3" style="padding:14px 10px;border-top:2px solid var(--border);text-align:center;font-weight:700;color:' + (fail > 0 ? 'var(--red)' : 'var(--green)') + ';">' +
    ok + ' of ' + total + ' scenario(s) updated' + (fail > 0 ? ', ' + fail + ' failed' : '') + '.' +
    '</td></tr>'
  );
  document.getElementById('btn-apply').disabled = false;
}

function selectAll(val) {
  document.querySelectorAll('#scan-results input[type="checkbox"]').forEach(b => b.checked = val);
}

function setInfo(id, html, cls) {
  const el = document.getElementById(id);
  el.innerHTML = html;
  el.className = 'info' + (cls ? ' ' + cls : '');
}

function showBadge(id, text, type) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'step-badge badge-' + type;
  el.classList.remove('hidden');
}

function esc(s) {
  const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML;
}
</script>
</body>
</html>`;

// ─── HTTP server ─────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const parsed = new URL(req.url, 'http://localhost');
  const pathname = parsed.pathname;
  const params = parsed.searchParams;

  try {
    if (req.method === 'GET' && pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(HTML);
    }
    else if (req.method === 'GET' && pathname === '/api/connect') {
      await handleConnect(res);
    }
    else if (req.method === 'POST' && pathname === '/api/select-org') {
      const body = await parseBody(req);
      await handleSelectOrg(body, res);
    }
    else if (req.method === 'GET' && pathname === '/api/scan') {
      await handleScan(params, res);
    }
    else if (req.method === 'POST' && pathname === '/api/apply') {
      const body = await parseBody(req);
      await handleApply(body, res);
    }
    else if (req.method === 'GET' && pathname === '/api/config') {
      const cfg = loadConfig();
      const hasToken = !!cfg.make?.token;
      if (cfg.make) delete cfg.make.token;
      sendJson(res, 200, { ...cfg, hasToken });
    }
    else if (req.method === 'POST' && pathname === '/api/set-token') {
      const body = await parseBody(req);
      await handleSetToken(body, res);
    }
    else if (req.method === 'POST' && pathname === '/api/clear-token') {
      await handleClearToken(res);
    }
    else if (req.method === 'POST' && pathname === '/api/config') {
      const body = await parseBody(req);
      saveConfig(body);
      sendJson(res, 200, { ok: true });
    }
    else {
      sendJson(res, 404, { error: 'Not found' });
    }
  } catch (e) {
    sendJson(res, 500, { error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`\n  Make Model Manager running at http://localhost:${PORT}\n`);
  console.log('  Open in your browser to get started.');
  console.log('  Token file:   ' + SECRET_PATH + (loadToken() ? ' (loaded)' : ' (empty — enter key in UI)'));
  console.log('  Config file:  ' + CONFIG_PATH);
  console.log();
});
