import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { spawn } from 'child_process';
import * as path from 'path';

// MCP 握手集成测试:真实 spawn 进程,走完整 initialize → tools/list → tools/call。
// fixture 指向不存在的数据库:只验证协议层与认证层(whoami/tools/list 不触库)。
// 整个 describe 共享一个服务进程,避免 Windows 上反复 spawn/kill 的竞态。

const ROOT = path.resolve(import.meta.dir, '..');
const CONFIG = path.join(import.meta.dir, 'fixtures', 'dbm.test.json');

class McpProc {
  private proc: any;
  private buffer = '';
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>();

  public start(token: string | undefined): Promise<void> {
    this.proc = spawn('bun', [path.join(ROOT, 'src', 'cli.ts'), 'serve', '--config', CONFIG], {
      env: { ...process.env, DBM_TOKEN: token ?? '' },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    this.proc.stdout.on('data', (d: Buffer) => this.onData(d));
    this.proc.stderr.on('data', () => {});
    return this.call('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'test', version: '0.0.1' }
    }).then((r) => {
      if (!r.serverInfo || r.serverInfo.name !== 'mcp-db') throw new Error('initialize 返回异常');
      this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) + '\n');
    });
  }

  private onData(d: Buffer) {
    this.buffer += d.toString();
    const lines = this.buffer.split(/\r?\n/);
    this.buffer = lines.pop() || '';
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        const p = this.pending.get(msg.id);
        if (p) {
          this.pending.delete(msg.id);
          if (msg.error) p.reject(new Error(msg.error.message));
          else p.resolve(msg.result);
        }
      } catch {}
    }
  }

  public call(method: string, params: any = {}): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }

  public stop() {
    try {
      this.proc.stdin.destroy();
      this.proc.kill();
    } catch {}
  }
}

describe('MCP server(stdio JSON-RPC)', () => {
  let proc: McpProc;

  beforeAll(async () => {
    proc = new McpProc();
    await proc.start('test-token-analyst-0001');
  });

  afterAll(() => proc.stop());

  test('initialize + ping', async () => {
    const pong = await proc.call('ping');
    expect(pong).toEqual({});
  }, 10000);

  test('tools/list 暴露流程化工具面(含脚本与审计)', async () => {
    const list = await proc.call('tools/list');
    const names = list.tools.map((t: any) => t.name);
    expect(names).toContain('dbm_query');
    expect(names).toContain('dbm_run');
    expect(names).toContain('dbm_preview');
    expect(names).toContain('dbm_list_scripts');
    expect(names).toContain('dbm_run_script');
    expect(names).toContain('dbm_audit');
    expect(list.tools.find((t: any) => t.name === 'dbm_run').inputSchema.required).toEqual(['env', 'executeSql']);
  }, 10000);

  test('dbm_list_scripts 返回注册表(fixture 内置 2 个)', async () => {
    const res = await proc.call('tools/call', { name: 'dbm_list_scripts', arguments: { env: 'dev' } });
    expect(res.structuredContent.count).toBe(2);
    expect(res.structuredContent.scripts.map((s: any) => s.id)).toContain('fix_region');
  }, 10000);

  test('dbm_whoami 返回身份与权限矩阵', async () => {
    const who = await proc.call('tools/call', { name: 'dbm_whoami', arguments: {} });
    expect(who.structuredContent.userId).toBe('u_analyst');
    expect(who.structuredContent.envs.dev.ops).toEqual(['read']);
    expect(who.isError).toBeUndefined();
  }, 10000);

  test('未知工具返回 isError + UNKNOWN_TOOL', async () => {
    const res = await proc.call('tools/call', { name: 'dbm_nope', arguments: {} });
    expect(res.isError).toBe(true);
    expect(res.structuredContent.code).toBe('UNKNOWN_TOOL');
  }, 10000);

  test('未知方法返回 -32601', async () => {
    await expect(proc.call('no/such/method', {})).rejects.toThrow('Method not found');
  }, 10000);

  test('数据库不可达时 dbm_query 返回可读错误而非挂死', async () => {
    const res = await proc.call('tools/call', { name: 'dbm_query', arguments: { env: 'dev', sql: 'SELECT 1' } });
    expect(res.isError).toBe(true);
    expect(typeof res.structuredContent.error).toBe('string');
  }, 20000);

  test('resources/list 只暴露有读权限的环境资源', async () => {
    const res = await proc.call('resources/list');
    const uris = res.resources.map((r: any) => r.uri);
    expect(uris).toContain('dbm://dev/typlm/tables');
    expect(uris).toContain('dbm://ga/typlm/tables');
  }, 10000);

  test('resources/templates/list 声明表元数据模板', async () => {
    const res = await proc.call('resources/templates/list');
    expect(res.resourceTemplates[0].uriTemplate).toBe('dbm://{env}/{schema}/{table}');
  }, 10000);

  test('resources/read 拒绝无法识别的 URI', async () => {
    await expect(proc.call('resources/read', { uri: 'dbm://bogus' })).rejects.toThrow('Invalid params');
  }, 10000);
});

describe('MCP server 认证(fail closed)', () => {
  test('无令牌:工具返回 UNAUTHENTICATED 而非静默放行', async () => {
    const proc = new McpProc();
    await proc.start(undefined);
    const res = await proc.call('tools/call', { name: 'dbm_whoami', arguments: {} });
    expect(res.isError).toBe(true);
    expect(res.structuredContent.code).toBe('UNAUTHENTICATED');
    proc.stop();
  }, 15000);

  test('错误令牌同样拒绝', async () => {
    const proc = new McpProc();
    await proc.start('wrong-token-value-xx');
    const res = await proc.call('tools/call', { name: 'dbm_query', arguments: { env: 'dev', sql: 'SELECT 1' } });
    expect(res.isError).toBe(true);
    expect(res.structuredContent.code).toBe('UNAUTHENTICATED');
    proc.stop();
  }, 15000);
});
