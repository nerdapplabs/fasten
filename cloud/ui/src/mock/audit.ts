// Mock audit rows — realistic shape matching the rivet SDK's AuditRow.
// Used to populate the v0.1 mock UI before backend wiring lands in v0.2.

export type Severity = 'info' | 'warn' | 'error' | 'critical';
export type Domain = 'user' | 'commerce' | 'config' | 'agent' | 'fleet';
export type Method = 'http' | 'mqtt' | 'cli' | 'scheduler' | 'ui' | 'agent_tool';

export interface AuditRow {
  id: string;
  ts: string; // HH:MM:SS local
  fullTs: string; // ISO
  code: string;
  domain: Domain;
  severity: Severity;
  actor: string;
  actorKind: 'user' | 'service' | 'schedule' | 'agent';
  target: string;
  method: Method;
  requestId: string;
  detail?: Record<string, string>;
}

export interface Site {
  id: string;
  name: string;
  region: string;
  nodes: number;
  rowsLast24h: number;
}

const codes: { code: string; domain: Domain; severity: Severity }[] = [
  { code: 'USER_CREATED', domain: 'user', severity: 'info' },
  { code: 'AUTH_LOGIN', domain: 'user', severity: 'info' },
  { code: 'AUTH_FAILED', domain: 'user', severity: 'warn' },
  { code: 'AUTH_LOGOUT', domain: 'user', severity: 'info' },
  { code: 'ORDER_PLACED', domain: 'commerce', severity: 'info' },
  { code: 'PAYMENT_PROCESSED', domain: 'commerce', severity: 'info' },
  { code: 'PAYMENT_FAILED', domain: 'commerce', severity: 'error' },
  { code: 'REFUND_ISSUED', domain: 'commerce', severity: 'info' },
  { code: 'CONFIG_NODE_UPDATED', domain: 'config', severity: 'info' },
  { code: 'CONFIG_VALIDATION_FAILED', domain: 'config', severity: 'warn' },
  { code: 'TOOL_CALLED', domain: 'agent', severity: 'info' },
  { code: 'POLICY_DENIED', domain: 'agent', severity: 'warn' },
  { code: 'NODE_CLAIMED', domain: 'fleet', severity: 'info' },
  { code: 'PIPELINE_DEPLOYED', domain: 'fleet', severity: 'info' },
];

const actors = [
  { name: 'admin', kind: 'user' as const },
  { name: 'praveen@nerdapplabs.com', kind: 'user' as const },
  { name: 'asha@acme.io', kind: 'user' as const },
  { name: 'system', kind: 'service' as const },
  { name: 'scheduler-cleanup', kind: 'schedule' as const },
  { name: 'claude-opus-4-7', kind: 'agent' as const },
];

const methods: Method[] = ['http', 'mqtt', 'cli', 'scheduler', 'ui', 'agent_tool'];

const targetTemplates: Record<Domain, string[]> = {
  user: ['u-42', 'u-7281', 'u-9001', 'u-1', 'session-a1b2'],
  commerce: ['ord-9001', 'ord-9002', 'pay-7281', 'cart-441', 'sub-12'],
  config: ['services/connector-rest/connection/url', 'services/buffer/retention_days', 'rules/threshold-warn'],
  agent: ['database.query', 'http.get', 'file.read', 'shell.exec', 'mailer.send'],
  fleet: ['node-gurugram-01', 'node-pune-line-2', 'p-123', 'p-481'],
};

const requestIds = [
  'a1b2c3d4', 'b2c3d4e5', 'c3d4e5f6', 'd4e5f607', 'e5f60718',
  'f6071829', '6071829a', '071829ab', '71829abc', '1829abcd',
];

let seq = 0;

function pick<T>(xs: T[]): T {
  return xs[(seq++ * 31337) % xs.length];
}

function clockMinusMinutes(min: number): { hms: string; iso: string } {
  const d = new Date(Date.now() - min * 60_000);
  const hms = d.toTimeString().slice(0, 8);
  const iso = d.toISOString();
  return { hms, iso };
}

export function makeRows(n = 64): AuditRow[] {
  const out: AuditRow[] = [];
  for (let i = 0; i < n; i++) {
    const c = pick(codes);
    const a = pick(actors);
    const m = pick(methods);
    const tgt = pick(targetTemplates[c.domain]);
    const rid = pick(requestIds);
    const { hms, iso } = clockMinusMinutes(i * 0.5);
    const detail: Record<string, string> = {};
    if (c.code === 'TOOL_CALLED') {
      detail.tokens = String(80 + (i % 200));
      detail.cost_usd = (0.0001 * (i % 50 + 1)).toFixed(4);
    }
    if (c.code === 'PAYMENT_FAILED') detail.reason = 'card_declined';
    if (c.code === 'CONFIG_NODE_UPDATED') detail.diff = '+url: https://api.acme.io';
    out.push({
      id: `evt-${(1e10 + i).toString(36)}`,
      ts: hms,
      fullTs: iso,
      code: c.code,
      domain: c.domain,
      severity: c.severity,
      actor: a.name,
      actorKind: a.kind,
      target: tgt,
      method: m,
      requestId: rid,
      detail: Object.keys(detail).length ? detail : undefined,
    });
  }
  return out;
}

export const mockSites: Site[] = [
  { id: 'site-pune-1', name: 'Pune Plant 1', region: 'IN-MH', nodes: 12, rowsLast24h: 8_421 },
  { id: 'site-gurugram-2', name: 'Gurugram DC 2', region: 'IN-HR', nodes: 8, rowsLast24h: 4_188 },
  { id: 'site-bangalore-rnd', name: 'Bangalore R&D', region: 'IN-KA', nodes: 4, rowsLast24h: 1_902 },
  { id: 'site-frankfurt-eu', name: 'Frankfurt EU', region: 'DE-HE', nodes: 6, rowsLast24h: 312 },
];

// Sparkline data — rows-per-minute over the past 60 minutes
export function makeActivity(): number[] {
  const out: number[] = [];
  for (let i = 0; i < 60; i++) {
    // Loosely sinusoidal with noise — looks like real traffic
    const base = 35 + Math.sin(i / 5) * 15;
    const noise = ((i * 1103) % 17) - 8;
    out.push(Math.max(0, Math.round(base + noise)));
  }
  return out;
}
