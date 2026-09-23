import { spawn, type ChildProcess } from 'child_process';
import type { McpProxyConnectionConfig, ProxyToolCall } from './config.js';
import type {
  BatchOpts,
  BatchResult,
  ColumnMeta,
  DatabaseProvider,
  HealthResult,
  QueryOpts,
  QueryResult,
  TableMeta
} from './types.js';

// ── MCP 桥接 Provider:把现成 MCP 数据源(dbhub / 本项目 mcp-db 等)当通道 ────
// 定位与诚实边界:上游服务的自有认证就是这道连接的「墙」;权限清单在此
// 连接上只驱动 UX 层检查。spawn 子进程 + stdio JSON-RPC,与 dbx-mcp 同构。

interface Pending {
  resolve: (v: any) => void;
  reject: (e: any) => void;
  timer: NodeJS.Timeout;
}

/** Markdown 表格文本 → 结构化行(兜底解析,值均为字符串) */
function parseMarkdownTable(md: string): { columns: string[]; rows: Record<string, any>[] } {
  const lines = (md || '').split(/\r?\n/).filter((l) => l.trim().startsWith('|'));
  if (lines.length < 2) return { columns: [], rows: [] };
  const columns = lines[0].split('|').map((c) => c.trim()).filter(Boolean);
  const rows: Record<string, any>[] = [];
  for (let i = 2; i < lines.length; i++) {
    if (lines[i].includes('---')) continue;
    const cells = lines[i].split('|').map((c) => c.trim()).slice(1, -1);
    if (cells.length === 0) continue;
    const row: Record<string, any> = {};
    columns.forEach((h, idx) => {
      let val: any = cells[idx] ?? null;
      if (val === 'NULL' || val === 'null' || val === '') val = null;
      row[h] = val;
    });
    rows.push(row);
  }
  return { columns, rows };
}

export class McpProxyProvider implements DatabaseProvider {
  public readonly dialect: string;
  private proc: ChildProcess | null = null;
  private requestId = 1;
  private pending = new Map<string, Pending>();
  private buffer = '';
  private initialized = false;
  private starting: Promise<void> | null = null;

  constructor(
    public readonly env: string,
    private cfg: McpProxyConnectionConfig
  ) {
    this.dialect = cfg.dialect ?? 'generic';
  }

  // ── 子进程与 JSON-RPC ──────────────────────────────────────────────────
  private ensureProcess(): Promise<void> {
    if (this.proc && this.initialized) return Promise.resolve();
    if (this.starting) return this.starting;
    this.starting = this.startProcess().finally(() => {
      this.starting = null;
    });
    return this.starting;
  }

  private startProcess(): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      let proc: ChildProcess;
      try {
        proc = spawn(this.cfg.command, this.cfg.args ?? [], {
          env: { ...process.env, ...this.cfg.env },
          stdio: ['pipe', 'pipe', 'pipe'],
          windowsHide: true
        });
      } catch (e: any) {
        return reject(new Error(`mcp-proxy(${this.env}) 启动失败:${e.message || e}`));
      }
      this.proc = proc;

      const fail = (msg: string) => {
        for (const [, p] of this.pending) {
          clearTimeout(p.timer);
          p.reject(new Error(msg));
        }
        this.pending.clear();
        this.initialized = false;
        if (this.proc === proc) this.proc = null;
        if (!settled) {
          settled = true;
          reject(new Error(msg));
        }
        try {
          proc.kill();
        } catch {}
      };

      proc.on('error', (e: any) => fail(`mcp-proxy(${this.env}) 进程错误:${e.message || e}`));
      proc.on('close', () => {
        if (this.proc === proc || this.initialized) fail(`mcp-proxy(${this.env}) 子进程已退出`);
      });
      proc.stdout?.on('data', (chunk: Buffer) => {
        this.buffer += chunk.toString();
        const lines = this.buffer.split(/\r?\n/);
        this.buffer = lines.pop() || '';
        for (const line of lines) {
          const text = line.trim();
          if (!text) continue;
          try {
            const msg = JSON.parse(text);
            if (msg.id !== undefined && this.pending.has(String(msg.id))) {
              const { resolve: res, reject: rej, timer } = this.pending.get(String(msg.id))!;
              clearTimeout(timer);
              this.pending.delete(String(msg.id));
              if (msg.error) rej(new Error(msg.error.message || JSON.stringify(msg.error)));
              else res(msg.result);
            }
          } catch {}
        }
      });
      proc.stderr?.on('data', () => {});
      proc.stdin?.on('error', () => {});

      const id = String(this.requestId++);
      const initTimer = setTimeout(() => fail(`mcp-proxy(${this.env}) 初始化超时`), 15000);
      this.pending.set(id, {
        timer: initTimer,
        resolve: () => {
          this.send({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
          this.initialized = true;
          if (!settled) {
            settled = true;
            resolve();
          }
        },
        reject: (e) => {
          fail(e.message || '初始化失败');
        }
      });
      this.send({
        jsonrpc: '2.0',
        id,
        method: 'initialize',
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'dbm-mcp-proxy', version: '0.1.0' }
        }
      });
    });
  }

  private send(payload: any): void {
    if (this.proc?.stdin?.writable) {
      this.proc.stdin.write(JSON.stringify(payload) + '\n');
    }
  }

  private async callTool(call: ProxyToolCall, vars: Record<string, string>, timeoutMs = 60000): Promise<any> {
    await this.ensureProcess();
    const args: Record<string, any> = {};
    for (const [k, v] of Object.entries(call.args ?? {})) {
      args[k] = v.replace(/\$(sql|maxRows)/g, (_, name: string) => vars[name] ?? '');
    }
    const id = String(this.requestId++);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`mcp-proxy(${this.env}) 上游工具 ${call.name} 超时(${Math.round(timeoutMs / 1000)}s)`));
      }, timeoutMs);
      this.pending.set(id, { timer, resolve, reject });
      this.send({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: call.name, arguments: args } });
    });
  }

  // ── 上游结果 → 结构化契约 ──────────────────────────────────────────────
  private parseUpstream(result: any): { columns: string[]; rows: Record<string, any>[] } {
    const text: string = (result?.content ?? [])
      .map((c: any) => c.text ?? '')
      .join('\n');
    if (this.cfg.parseMode !== 'markdown') {
      try {
        const data = JSON.parse(text);
        // 兼容三种形态:{columns, rows} | {data: [...]} | 裸数组
        if (Array.isArray(data)) {
          const rows = data as Record<string, any>[];
          return { columns: rows.length ? Object.keys(rows[0]) : [], rows };
        }
        if (Array.isArray(data?.rows)) {
          return { columns: Array.isArray(data?.columns) ? data.columns : data.rows.length ? Object.keys(data.rows[0]) : [], rows: data.rows };
        }
        if (Array.isArray(data?.data)) {
          return { columns: data.data.length ? Object.keys(data.data[0]) : [], rows: data.data };
        }
      } catch {
        // 落到 markdown 解析
      }
    }
    return parseMarkdownTable(text);
  }

  // ── DatabaseProvider 实现 ──────────────────────────────────────────────
  public async healthCheck(role?: string): Promise<HealthResult> {
    const started = Date.now();
    try {
      await this.rawQuery('SELECT 1', 1);
      return { ok: true, latencyMs: Date.now() - started, role };
    } catch (e: any) {
      return { ok: false, latencyMs: Date.now() - started, error: e?.message ?? String(e), role };
    }
  }

  private async rawQuery(sql: string, maxRows: number): Promise<{ columns: string[]; rows: Record<string, any>[] }> {
    const result = await this.callTool(this.cfg.tools.query, { sql, maxRows: String(maxRows) });
    if (result?.isError) {
      const text = (result.content ?? []).map((c: any) => c.text ?? '').join(' ');
      throw new Error(`上游返回错误:${text.slice(0, 200)}`);
    }
    return this.parseUpstream(result);
  }

  public async executeQuery(sql: string, opts: QueryOpts = {}): Promise<QueryResult> {
    const maxRows = Math.max(1, Math.min(opts.maxRows ?? 200, 2000));
    const inner = sql.trim().replace(/;+\s*$/, '');
    const started = Date.now();
    // 上游工具自限流;包裹语法随上游方言差异大,这里信任 maxRows 参数
    const { columns, rows } = await this.rawQuery(inner, maxRows + 1);
    const truncated = rows.length > maxRows;
    return {
      columns,
      rows: truncated ? rows.slice(0, maxRows) : rows,
      rowCount: Math.min(rows.length, maxRows),
      truncated,
      latencyMs: Date.now() - started
    };
  }

  public async executeBatch(sql: string, opts: BatchOpts = {}): Promise<BatchResult> {
    if (!this.cfg.tools.batch) {
      throw new Error(`连接 ${this.env} 的 mcp-proxy 未配置 tools.batch,无法执行写操作`);
    }
    const started = Date.now();
    const text = sql.trim().replace(/;+\s*$/, '');
    const result = await this.callTool(this.cfg.tools.batch, { sql: text, maxRows: '0' });
    const textOut = (result?.content ?? []).map((c: any) => c.text ?? '').join('\n');
    const ok = !result?.isError;
    return {
      statements: [{ sql: text.slice(0, 200), ok, command: 'UPSTREAM', rowCount: null, error: ok ? undefined : textOut.slice(0, 200) }],
      text: ok ? `OK(上游):${textOut.slice(0, 120)}` : `失败(上游):${textOut.slice(0, 200)}`,
      latencyMs: Date.now() - started
    };
  }

  public async listTables(schema: string, role?: string): Promise<TableMeta[]> {
    this.assertDialectForCatalog();
    const q =
      this.dialect === 'mysql'
        ? `SELECT TABLE_NAME AS table_name, TABLE_TYPE AS table_type, TABLE_COMMENT AS comment, TABLE_ROWS AS estimated_rows, NULL AS size_bytes FROM information_schema.TABLES WHERE TABLE_SCHEMA = '${schema}' ORDER BY TABLE_NAME`
        : `SELECT t.table_name, t.table_type, NULL::text AS comment, NULL::bigint AS estimated_rows, NULL::bigint AS size_bytes FROM information_schema.tables t WHERE t.table_schema = '${schema}' AND t.table_type IN ('BASE TABLE','VIEW') ORDER BY t.table_name`;
    const { rows } = await this.rawQuery(q, 5000);
    return rows.map((r: any) => ({
      schema,
      name: String(r.table_name),
      type: String(r.table_type ?? 'BASE TABLE'),
      comment: r.comment ?? null,
      estimatedRows: r.estimated_rows != null ? Number(r.estimated_rows) : null,
      sizeBytes: r.size_bytes != null ? Number(r.size_bytes) : null
    }));
  }

  public async describeTable(schema: string, table: string, role?: string): Promise<ColumnMeta[]> {
    this.assertDialectForCatalog();
    const q =
      this.dialect === 'mysql'
        ? `SELECT COLUMN_NAME AS name, COLUMN_TYPE AS raw_type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS default_val, COLUMN_KEY AS key_kind, COLUMN_COMMENT AS comment FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '${schema}' AND TABLE_NAME = '${table}' ORDER BY ORDINAL_POSITION`
        : `SELECT c.column_name AS name, c.data_type AS raw_type, c.is_nullable AS nullable, c.column_default AS default_val, NULL AS key_kind, NULL AS comment FROM information_schema.columns c WHERE c.table_schema = '${schema}' AND c.table_name = '${table}' ORDER BY c.ordinal_position`;
    const { rows } = await this.rawQuery(q, 2000);
    return rows.map((r: any) => ({
      name: String(r.name),
      rawType: String(r.raw_type ?? ''),
      nullable: String(r.nullable ?? 'YES').toUpperCase() === 'YES',
      isPk: String(r.key_kind ?? '') === 'PRI',
      defaultVal: r.default_val ?? null,
      comment: r.comment ?? null,
      references: null
    }));
  }

  private assertDialectForCatalog(): void {
    if (this.dialect !== 'postgres' && this.dialect !== 'mysql') {
      throw new Error(
        `连接 ${this.env} 的 mcp-proxy 未声明 dialect(postgres/mysql),无法探测表结构;请为上游配置 dialect 或直接使用其原生工具`
      );
    }
  }

  public async close(): Promise<void> {
    const proc = this.proc;
    this.proc = null;
    this.initialized = false;
    if (proc) {
      try {
        proc.stdin?.destroy();
        proc.kill();
      } catch {}
    }
  }
}
