/* A small Model Context Protocol server, with no SDK, so AI agents can grade a website.
   The protocol is JSON-RPC 2.0, one message per line over stdin and stdout. */
import { scanAddress } from './scan.js';

const KNOWN_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

export const TOOL = {
  name: 'check_website',
  title: 'Check a website\'s security basics',
  description: "Grades a public website's security basics from A to F: HTTPS and its certificate, security headers, cookies, forms, email spoofing records (SPF, DMARC, DKIM), security blocklists, risky software versions and domain expiry. Returns the grade, a plain-English summary and copy-paste fixes for the host the site runs on. Read-only: it loads the homepage the way a browser does and reads public records. It covers the basics, so it isn't a penetration test.",
  inputSchema: {
    type: 'object',
    properties: { url: { type: 'string', description: 'The website address, such as example.com or https://example.com' } },
    required: ['url'],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
};

const brief = (r) => [
  `${r.host}: grade ${r.grade}, ${r.score}/100. ${r.summary.headline}`,
  r.caveat ? `Caveat: ${r.caveat}` : '',
  ...r.summary.risks.map((x) => `- ${x.text}`),
  r.summary.next ? `Fastest win: ${r.summary.next.title} (${r.summary.next.time}, +${r.summary.next.points} points).` : '',
].filter(Boolean).join('\n');

/* One incoming message -> the reply to send, or null when none is due (notifications). */
export async function handle(msg, { scan = scanAddress } = {}) {
  const { id, method, params } = msg ?? {};
  const isCall = id !== undefined && id !== null;
  const reply = (result) => ({ jsonrpc: '2.0', id, result });
  const error = (code, message) => ({ jsonrpc: '2.0', id: isCall ? id : null, error: { code, message } });

  if (typeof method !== 'string') return error(-32600, 'Invalid request.');
  if (!isCall) return null;
  switch (method) {
    case 'initialize':
      return reply({
        protocolVersion: KNOWN_VERSIONS.includes(params?.protocolVersion) ? params.protocolVersion : KNOWN_VERSIONS[0],
        capabilities: { tools: {} },
        serverInfo: { name: 'dare-check', title: 'DARE CHECK', version: '1.0.0' },
      });
    case 'ping':
      return reply({});
    case 'tools/list':
      return reply({ tools: [TOOL] });
    case 'tools/call': {
      if (params?.name !== TOOL.name) return error(-32602, `Unknown tool: ${params?.name}`);
      const url = params?.arguments?.url;
      if (typeof url !== 'string' || !url.trim()) return reply({ isError: true, content: [{ type: 'text', text: 'Give a website address in "url", such as example.com.' }] });
      const r = await scan(url);
      if (!r.ok) return reply({ isError: true, content: [{ type: 'text', text: r.error }] });
      return reply({ content: [{ type: 'text', text: brief(r) }, { type: 'text', text: JSON.stringify(r) }] });
    }
    default:
      return error(-32601, `Method not found: ${method}`);
  }
}

/* Reads messages line by line and answers each. stdout belongs to the protocol, so nothing else writes there. */
export async function serve({ input = process.stdin, output = process.stdout, scan } = {}) {
  const { createInterface } = await import('node:readline');
  const pending = new Set();
  for await (const line of createInterface({ input, crlfDelay: Infinity })) {
    if (!line.trim()) continue;
    const task = (async () => {
      let msg;
      try { msg = JSON.parse(line); } catch {
        output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'That wasn\'t valid JSON.' } }) + '\n');
        return;
      }
      const out = await handle(msg, { scan }).catch(() => ({ jsonrpc: '2.0', id: msg?.id ?? null, error: { code: -32603, message: 'Internal error.' } }));
      if (out) output.write(JSON.stringify(out) + '\n');
    })();
    pending.add(task);
    task.finally(() => pending.delete(task));
  }
  await Promise.all(pending);
}
