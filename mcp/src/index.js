#!/usr/bin/env node
/**
 * REWORK Proof — an MCP server for checking whether delivered work is genuine.
 *
 * The audience is an AI agent that has been handed a pull request, a
 * contractor's portfolio, or a credential, and needs to answer "is this
 * actually theirs?" without taking anyone's word for it.
 *
 * ZERO DEPENDENCIES, DELIBERATELY. MCP's stdio transport is newline-delimited
 * JSON-RPC 2.0, which is small enough to implement outright. A tool whose
 * entire purpose is verifying authenticity has no business asking you to
 * trust ninety transitive packages first - the supply chain is part of the
 * claim. Node 20's global fetch covers the rest.
 *
 * THE ONE RULE OF STDIO TRANSPORT: stdout carries protocol frames and nothing
 * else. A stray console.log corrupts the stream and the client disconnects
 * with an unhelpful parse error, so every diagnostic here goes to stderr.
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const API = (process.env.REWORK_API_URL || 'https://api.reworkdigital.io/api/v1').replace(/\/$/, '');

const readJson = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, name), 'utf8'));

// The version a client sees in serverInfo is package.json's, read at start,
// so it cannot drift from what npm published. It was a typed '1.0.0' while
// the package was 1.1.0 (found 2026-10-18); check_rework_proof_mcp.py pins
// this now. package.json sits one level up from src/, inside the tarball.
const SERVER_VERSION = readJson('../package.json').version;

// Protocol revisions this server understands, newest first, read further
// down from mcp-spec.json (SUPPORTED_PROTOCOLS and STATELESS_PROTOCOLS).
const HTTP_TIMEOUT_MS = 15000;

const log = (...a) => process.stderr.write(a.join(' ') + '\n');

/**
 * What REWORK's assurance levels mean, and — more importantly — what they do
 * not. Read from `assurance.json` beside this file rather than fetched: an
 * agent asking "how much does this prove?" should get the same answer when
 * the API is unreachable, and the honest ceiling on a claim is not something
 * to look up over the network. The same file is what the Action README and
 * the reworkdigital.io/github page render, so every surface states one
 * ceiling.
 */
const ASSURANCE_SPEC = readJson('assurance.json');
// The tools and the fixed sentences this server returns (see TOOLS below).
const SPEC = readJson('mcp-spec.json');

// Two eras of the protocol, both spoken here:
//   handshake  the client sends `initialize` first; its revision is echoed
//              when it is known, otherwise the newest is offered.
//   stateless  (2026-07-28) no handshake. Every request names its revision
//              and the client's capabilities in `params._meta`, every result
//              says `resultType`, and `server/discover` answers what the
//              handshake used to.
// A request carrying the stateless `_meta` is served that way; anything else
// is served as before.
const SUPPORTED_PROTOCOLS = SPEC.protocols.handshake;
const STATELESS_PROTOCOLS = SPEC.protocols.stateless;
const META_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_CLIENT_CAPABILITIES = 'io.modelcontextprotocol/clientCapabilities';
const META_SERVER_INFO = 'io.modelcontextprotocol/serverInfo';
const LIST_TTL_MS = 3600000;
const ASSURANCE = ASSURANCE_SPEC.levels;

/**
 * Which commit-message declarations the checks count as AI assistance, from
 * `ai-trailers.json`: the same definition the Action and the App check read.
 * Listed in the explanation so an agent knows what "declared" means here. A
 * declaration is something the author wrote; a count of zero means nothing
 * was declared, never that no tool was used.
 */
const AI_TRAILERS = readJson('ai-trailers.json');
const AI_DECLARATION = {
  reads: SPEC.ai_declaration.reads,
  tools: AI_TRAILERS.tools.map((t) => t.name),
  zero_means: SPEC.ai_declaration.zero_means,
  declared_means: SPEC.ai_declaration.declared_means,
};

const CREDENTIAL_TYPES = SPEC.credential_types;

// ── tools ──────────────────────────────────────────────────────────────────

/**
 * The tools, from `mcp-spec.json`: one definition for this server and for the
 * hosted one REWORK runs (the Claude directory lists a server by URL, and it
 * requires each tool to carry a title and a read-only or destructive hint).
 * Every tool here only reads, so each carries readOnlyHint.
 */
const TOOLS = SPEC.tools.map((t) => JSON.parse(JSON.stringify(t)));
// Here the lookup hashes the credential in this process, which is a stronger
// promise than the shared wording makes, so this server says so.
TOOLS.find((t) => t.name === 'lookup_rework_attestation').inputSchema.properties.credential.description =
  'The VC-JWT. Hashed locally and never sent anywhere. For a certificate credential, the certificate id it names (already public) is looked up as well.';

async function http(path, { method = 'GET', body } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(`${API}${path}`, {
      method,
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctl.signal,
    });
    const text = await res.text();
    let parsed;
    try { parsed = JSON.parse(text); } catch { parsed = { raw: text.slice(0, 500) }; }
    if (!res.ok) throw new Error(`REWORK API ${res.status}: ${JSON.stringify(parsed).slice(0, 300)}`);
    return parsed;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * What a credential SAYS it is, read without checking its signature: the kind
 * of REWORK credential, and the certificate it names when it is a certificate
 * credential. Never evidence on its own: a forger writes these too.
 */
function stated(credential) {
  const out = { type: null, certificate_id: null };
  const parts = typeof credential === 'string' ? credential.trim().split('.') : [];
  if (parts.length !== 3) return out;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return out;
  }
  const vc = payload && typeof payload === 'object' ? payload.vc : null;
  if (!vc || typeof vc !== 'object' || Array.isArray(vc)) return out;
  for (const kind of Array.isArray(vc.type) ? vc.type : []) {
    if (typeof kind === 'string' && Object.prototype.hasOwnProperty.call(CREDENTIAL_TYPES, kind)) {
      out.type = kind;
      break;
    }
  }
  if (out.type === SPEC.registry.certificate_type) {
    const subject = vc.credentialSubject;
    const achievement = subject && typeof subject === 'object' ? subject.achievement : null;
    const found = (achievement && typeof achievement === 'object' ? achievement.identifier : null) || payload.jti;
    if (typeof found === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(found)) out.certificate_id = found;
  }
  return out;
}

/**
 * What REWORK holds for a certificate id. Only the id is sent, and it is
 * already public on the certificate's own page; `found` and `revoked` are null
 * when the API could not be reached, so "could not look" is never reported as
 * "no such certificate".
 */
async function certificateRecord(id) {
  const fallback = { id, found: null, revoked: null, verify_url: `${SPEC.site}/verify/${id}` };
  try {
    const res = await http(`/proofs/certificates/${encodeURIComponent(id)}/status`);
    return {
      id,
      found: typeof res.found === 'boolean' ? res.found : null,
      revoked: typeof res.revoked === 'boolean' ? res.revoked : null,
      verify_url: fallback.verify_url,
    };
  } catch (err) {
    log(`certificate ${id} could not be read: ${err.message}`);
    return fallback;
  }
}

async function callTool(name, args) {
  if (name === 'verify_rework_credential') {
    const credential = (args && args.credential) || '';
    if (!credential.trim()) throw new Error(SPEC.errors.credential_required);
    const res = await http('/proofs/credentials/verify', {
      method: 'POST',
      body: { credential },
    });
    const subject = res.credential_subject || {};
    const assurance = subject.assurance;
    // The API checks the signature, the expiry, and whether REWORK has since
    // revoked the credential. `revoked` is true, false, or null (nothing to
    // check, or it could not be read); a server that predates the check
    // sends nothing, which is null too.
    const revoked = typeof res.revoked === 'boolean' ? res.revoked : null;
    // The API has checked the signature by here, so what the credential
    // states about its kind is REWORK's word.
    const kind = (res.valid === true || revoked === true) ? stated(credential).type : null;
    let note;
    if (revoked === true) note = SPEC.notes.revoked;
    else if (assurance && ASSURANCE[assurance]) note = ASSURANCE[assurance].does_not_mean;
    // A kind of credential with no assurance level by design (a certificate,
    // a receipt, a passport): say what it is and its ceiling.
    else if ((assurance === undefined || assurance === null) && kind) note = `${CREDENTIAL_TYPES[kind]} ${SPEC.notes.no_assurance_level}`;
    else note = SPEC.notes.unknown_assurance;
    return {
      valid: res.valid === true,
      reason: res.reason || null,
      revoked,
      issuer: res.issuer || null,
      credential_type: kind,
      credential_subject: subject,
      // An agent that only reads `valid` would treat every credential as
      // equally strong. Ship the ceiling alongside the verdict.
      assurance_note: note,
    };
  }

  if (name === 'get_rework_issuer_keys') {
    return await http('/proofs/credentials/jwks.json');
  }

  if (name === 'explain_rework_assurance') {
    const level = args && args.assurance;
    if (level) {
      const entry = ASSURANCE[level];
      if (!entry) {
        return { error: `unknown assurance level: ${level}`, known: Object.keys(ASSURANCE) };
      }
      return { assurance: level, ...entry, ai_declaration: AI_DECLARATION };
    }
    return {
      assurance_levels: ASSURANCE,
      what_the_check_reads: ASSURANCE_SPEC.reads,
      ai_declaration: AI_DECLARATION,
      credential_types: CREDENTIAL_TYPES,
    };
  }

  if (name === 'lookup_rework_attestation') {
    let digest = args && args.digest;
    if (!digest && args && args.credential) {
      // Hashed locally: the credential itself never leaves this process.
      digest = crypto.createHash('sha256').update(args.credential, 'utf8').digest('hex');
    }
    if (!digest || !/^[0-9a-f]{64}$/.test(String(digest).toLowerCase())) {
      throw new Error(SPEC.errors.digest_required);
    }
    digest = String(digest).toLowerCase();
    try {
      const record = await http(`/github-app/attestations/${digest}`);
      return {
        ...record,
        assurance_note: SPEC.notes.issued,
      };
    } catch (err) {
      if (String(err.message).includes('REWORK API 404')) {
        const said = args && args.credential ? stated(args.credential) : { type: null, certificate_id: null };
        if (SPEC.registry.signed_afresh.includes(said.type)) {
          // Signed afresh on every download: no two copies share a digest, so
          // there was never a record to find, and "not issued" would be a
          // false alarm about a genuine credential.
          const answer = { issued: null, digest_sha256: digest, credential_type: said.type };
          if (said.certificate_id) answer.certificate = await certificateRecord(said.certificate_id);
          answer.assurance_note = SPEC.notes.registry_not_kept;
          return answer;
        }
        return {
          issued: false,
          digest_sha256: digest,
          assurance_note: SPEC.notes.not_issued,
        };
      }
      throw err;
    }
  }

  throw new Error(`unknown tool: ${name}`);
}

// ── JSON-RPC plumbing ──────────────────────────────────────────────────────

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function result(id, value) { send({ jsonrpc: '2.0', id, result: value }); }
function failure(id, code, message, data) {
  const error = data === undefined ? { code, message } : { code, message, data };
  send({ jsonrpc: '2.0', id, error });
}

const serverInfo = () => ({
  name: SPEC.server.name, title: SPEC.server.title, version: SERVER_VERSION, description: SPEC.server.description,
});

const TOOL_NAMES = new Set(TOOLS.map((t) => t.name));

/** A request of the stateless era: answered whole, with no handshake before it. */
async function handleStateless(msg, meta) {
  const { id, method, params } = msg;
  if (id === undefined || id === null) return undefined;
  const requested = meta[META_VERSION];
  if (!STATELESS_PROTOCOLS.includes(requested)) {
    return failure(id, -32022, 'Unsupported protocol version',
      { supported: [...STATELESS_PROTOCOLS, ...SUPPORTED_PROTOCOLS], requested });
  }
  const caps = meta[META_CLIENT_CAPABILITIES];
  if (!caps || typeof caps !== 'object' || Array.isArray(caps)) {
    return failure(id, -32602, `Invalid params: params._meta must carry ${META_CLIENT_CAPABILITIES} (an object, which may be empty)`);
  }
  if (method === 'server/discover') {
    return result(id, {
      resultType: 'complete',
      supportedVersions: [...STATELESS_PROTOCOLS, ...SUPPORTED_PROTOCOLS],
      capabilities: { tools: {} },
      instructions: SPEC.server.instructions,
      ttlMs: LIST_TTL_MS,
      cacheScope: 'public',
      _meta: { [META_SERVER_INFO]: serverInfo() },
    });
  }
  if (method === 'tools/list') {
    return result(id, { resultType: 'complete', tools: TOOLS, ttlMs: LIST_TTL_MS, cacheScope: 'public' });
  }
  if (method === 'tools/call') {
    const name = params && params.name;
    const args = params && params.arguments;
    // No such tool, or arguments that are not an object: the request is
    // malformed, a protocol error. What is wrong inside the arguments is the
    // tool's to report, as a result the model can read.
    if (typeof name !== 'string' || !TOOL_NAMES.has(name)) return failure(id, -32602, `Unknown tool: ${name}`);
    if (args !== undefined && args !== null && (typeof args !== 'object' || Array.isArray(args))) {
      return failure(id, -32602, 'Invalid params: arguments must be an object');
    }
    try {
      const out = await callTool(name, args || {});
      return result(id, {
        resultType: 'complete',
        content: [{ type: 'text', text: JSON.stringify(out, null, 2) }],
        structuredContent: out,
        isError: false,
      });
    } catch (err) {
      return result(id, {
        resultType: 'complete',
        content: [{ type: 'text', text: `Tool ${name} failed: ${err.message}` }],
        isError: true,
      });
    }
  }
  return failure(id, -32601, `Method not found: ${method}`);
}

async function handle(msg) {
  const { id, method, params } = msg;

  const meta = params && params._meta && typeof params._meta === 'object' ? params._meta : null;
  if (meta && META_VERSION in meta) return handleStateless(msg, meta);

  // A notification has no id and must never be answered - replying to one is
  // a protocol violation the client reports as an unsolicited response.
  const isNotification = id === undefined || id === null;

  if (method === 'initialize') {
    const asked = params && params.protocolVersion;
    return result(id, {
      protocolVersion: SUPPORTED_PROTOCOLS.includes(asked) ? asked : SUPPORTED_PROTOCOLS[0],
      capabilities: { tools: { listChanged: false } },
      serverInfo: serverInfo(),
      instructions: SPEC.server.instructions,
    });
  }

  if (method === 'notifications/initialized' || method === 'initialized') return;
  if (method === 'ping') return isNotification ? undefined : result(id, {});

  if (method === 'tools/list') {
    return result(id, { tools: TOOLS });
  }

  if (method === 'tools/call') {
    const name = params && params.name;
    try {
      const out = await callTool(name, (params && params.arguments) || {});
      // The same answer twice: as data a client can read field by field
      // (each tool declares its outputSchema), and as text for a client that
      // only reads text.
      return result(id, {
        content: [{ type: 'text', text: JSON.stringify(out, null, 2) }],
        structuredContent: out,
        isError: false,
      });
    } catch (err) {
      // A tool that fails is a result, not a transport error: the model needs
      // to see why so it can adapt, and a JSON-RPC error would hide it.
      return result(id, {
        content: [{ type: 'text', text: `Tool ${name} failed: ${err.message}` }],
        isError: true,
      });
    }
  }

  if (isNotification) return;
  return failure(id, -32601, `Method not found: ${method}`);
}

let buffer = '';
const inFlight = new Set();
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let nl;
  while ((nl = buffer.indexOf('\n')) !== -1) {
    const line = buffer.slice(0, nl).trim();
    buffer = buffer.slice(nl + 1);
    if (!line) continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch (err) {
      log(`dropping unparseable frame: ${err.message}`);
      continue;
    }
    const work = Promise.resolve(handle(msg)).catch((err) => {
      log(`handler error: ${err.stack || err.message}`);
      if (msg && msg.id !== undefined && msg.id !== null) {
        failure(msg.id, -32603, `Internal error: ${err.message}`);
      }
    });
    inFlight.add(work);
    work.finally(() => inFlight.delete(work));
  }
});

// When the client closes its end, answer what it already asked before
// leaving. Exiting at once dropped any tool call still waiting on the
// network, so a client that sent a call and then closed got no answer.
process.stdin.on('end', () => {
  Promise.allSettled([...inFlight]).then(() => process.exit(0));
});
log(`rework-proof MCP server ready (api=${API})`);
