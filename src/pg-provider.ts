import { Pool, type PoolClient } from 'pg';
import type { PgConnectionConfig } from './config.js';
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
import { firstKeywordOf } from './sql-guard.js';

// ── PostgreSQL 直连 Provider(模式 A:角色 × 连接池)─────────────────────────
// 每个角色一个独立 Pool,凭证互不相通;请求路径上不存在换池/提权通道。
// 类型保真:pg 驱动原生解析(int4→number、bool→boolean、timestamptz→Date)。
// 注:int8/numeric 超过安全范围时 pg 返回字符串,由前端按列类型处理。

/** 可用子查询包裹限流的读语句形态 */
const WRAPPABLE = new Set(['SELECT', 'WITH', 'TABLE', 'VALUES']);

export class DirectPgProvider implements DatabaseProvider {
  public readonly dialect = 'postgres';
  private pools = new Map<string, Pool>();

  constructor(
    public readonly env: string,
    private cfg: PgConnectionConfig
  ) {}

  /** 默认探测角色:配置里第一个(建议把 analyst 放最前,探测的是最小权限路径) */
  private defaultRole(): string {
    return Object.keys(this.cfg.roles)[0];
  }

  public pool(role: string): Pool {
    const cred = this.cfg.roles[role];
    if (!cred) {
      throw new Error(`角色 "${role}" 未在连接 ${this.env} 配置凭证(可用:${Object.keys(this.cfg.roles).join(', ')})`);
    }
    let pool = this.pools.get(role);
    if (!pool) {
      pool = new Pool({
        host: this.cfg.host,
        port: this.cfg.port,
        database: this.cfg.database,
        user: cred.user,
        password: cred.password,
        max: cred.max ?? 4,
        statement_timeout: cred.statementTimeoutMs ?? 30_000,
        connectionTimeoutMillis: 8000,
        ssl: this.cfg.ssl ? { rejectUnauthorized: false } : undefined
      });
      pool.on('error', (e) => console.error(`[dbm:${this.env}] pool error:`, e.message));
      this.pools.set(role, pool);
    }
    return pool;
  }

  private async withClient<T>(role: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool(role).connect();
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }

  public async healthCheck(role?: string): Promise<HealthResult> {
    const r = role ?? this.defaultRole();
    const started = Date.now();
    try {
      await this.pool(r).query('SELECT 1');
      return { ok: true, latencyMs: Date.now() - started, role: r };
    } catch (e: any) {
      return { ok: false, latencyMs: Date.now() - started, error: friendlyPgError(e), role: r };
    }
  }

  public async listTables(schema: string, role?: string): Promise<TableMeta[]> {
    const res = await this.pool(role ?? this.defaultRole()).query<{
      table_name: string;
      table_type: string;
      comment: string | null;
      est_rows: number | null;
      total_bytes: number | null;
    }>(
      `SELECT t.table_name,
              t.table_type,
              obj_description(format('%I.%I', t.table_schema, t.table_name)::regclass, 'pg_class') AS comment,
              c.reltuples::bigint AS est_rows,
              CASE WHEN c.oid IS NULL THEN NULL ELSE pg_total_relation_size(c.oid) END AS total_bytes
       FROM information_schema.tables t
       LEFT JOIN pg_class c ON c.oid = format('%I.%I', t.table_schema, t.table_name)::regclass
       WHERE t.table_schema = $1 AND t.table_type IN ('BASE TABLE', 'VIEW', 'FOREIGN')
       ORDER BY t.table_name`,
      [schema]
    );
    return res.rows.map((r) => ({
      schema,
      name: r.table_name,
      type: r.table_type,
      comment: r.comment ?? null,
      estimatedRows: r.est_rows !== null && r.est_rows >= 0 ? Number(r.est_rows) : null,
      sizeBytes: r.total_bytes !== null ? Number(r.total_bytes) : null
    }));
  }

  public async describeTable(schema: string, table: string, role?: string): Promise<ColumnMeta[]> {
    const pool = this.pool(role ?? this.defaultRole());
    const cols = await pool.query<{
      column_name: string;
      data_type: string;
      udt_name: string;
      character_maximum_length: number | null;
      numeric_precision: number | null;
      numeric_scale: number | null;
      is_nullable: string;
      column_default: string | null;
      comment: string | null;
    }>(
      `SELECT c.column_name, c.data_type, c.udt_name,
              c.character_maximum_length, c.numeric_precision, c.numeric_scale,
              c.is_nullable, c.column_default,
              pg_catalog.col_description(format('%I.%I', $1::text, $2::text)::regclass, c.ordinal_position) AS comment
       FROM information_schema.columns c
       WHERE c.table_schema = $1 AND c.table_name = $2
       ORDER BY c.ordinal_position`,
      [schema, table]
    );
    // 主键走 pg_catalog:information_schema.table_constraints 对非 owner 角色隐藏约束
    const pk = await pool.query<{ attname: string }>(
      `SELECT a.attname
       FROM pg_index i
       JOIN pg_class t ON t.oid = i.indrelid
       JOIN pg_namespace n ON n.oid = t.relnamespace
       JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(i.indkey)
       WHERE i.indisprimary AND n.nspname = $1 AND t.relname = $2`,
      [schema, table]
    );
    const pkSet = new Set(pk.rows.map((r) => r.attname));

    // 外键:Agent 推断 JOIN 关系的上下文。
    // 走 pg_catalog 而非 information_schema——后者的视图与参数下推组合会触发 42P08
    const fk = await pool.query<{ column_name: string; foreign_table: string; foreign_column: string }>(
      `SELECT a.attname AS column_name, cf.relname AS foreign_table, af.attname AS foreign_column
       FROM pg_constraint con
       JOIN pg_class ct ON ct.oid = con.conrelid
       JOIN pg_namespace nt ON nt.oid = ct.relnamespace
       JOIN pg_class cf ON cf.oid = con.confrelid
       CROSS JOIN LATERAL generate_subscripts(con.conkey, 1) AS i
       JOIN pg_attribute a ON a.attrelid = ct.oid AND a.attnum = con.conkey[i]
       JOIN pg_attribute af ON af.attrelid = cf.oid AND af.attnum = con.confkey[i]
       WHERE con.contype = 'f' AND nt.nspname = $1 AND ct.relname = $2`,
      [schema, table]
    );
    const fkMap = new Map(fk.rows.map((r) => [r.column_name, { table: r.foreign_table, column: r.foreign_column }]));

    return cols.rows.map((r) => ({
      name: r.column_name,
      rawType: formatRawType(r),
      nullable: r.is_nullable === 'YES',
      isPk: pkSet.has(r.column_name),
      defaultVal: r.column_default ?? null,
      comment: r.comment ?? null,
      references: fkMap.get(r.column_name) ?? null
    }));
  }

  public async executeQuery(sql: string, opts: QueryOpts = {}): Promise<QueryResult> {
    const role = opts.role ?? this.defaultRole();
    const maxRows = Math.max(1, Math.min(opts.maxRows ?? 200, 2000));
    const inner = sql.trim().replace(/;+\s*$/, '');
    const started = Date.now();

    // SHOW/EXPLAIN 不能被子查询包裹:直接执行(结果集本身很小),截断保护仍在
    const wrappable = WRAPPABLE.has(firstKeywordOf(inner));
    const finalSql = wrappable
      ? `SELECT * FROM (${inner}) AS dbm_sub LIMIT ${maxRows + 1}`
      : inner;

    const res = await this.pool(role).query(finalSql).catch((e: any) => {
      throw new Error(friendlyPgError(e));
    });
    const fields = res.fields ?? [];
    const truncated = res.rows.length > maxRows;
    const rows = truncated ? res.rows.slice(0, maxRows) : res.rows;

    return {
      columns: fields.map((f: any) => f.name),
      rows: rows as Record<string, any>[],
      rowCount: rows.length,
      truncated,
      latencyMs: Date.now() - started
    };
  }

  public async executeBatch(sql: string, opts: BatchOpts = {}): Promise<BatchResult> {
    const role = opts.role ?? this.defaultRole();
    const useTx = opts.transaction !== false;
    const text = sql.trim().replace(/;+\s*$/, '');
    const started = Date.now();

    return this.withClient(role, async (client) => {
      const statements: BatchResult['statements'] = [];
      if (useTx) await client.query('BEGIN');
      try {
        // 简单查询协议:多语句一次下发,pg 返回每个语句的 result(数组)
        const raw: any = await client.query(text);
        const results = Array.isArray(raw) ? raw : [raw];
        for (const r of results) {
          statements.push({
            sql: '',
            ok: true,
            command: r.command ?? '',
            rowCount: typeof r.rowCount === 'number' ? r.rowCount : null
          });
        }
        if (useTx) await client.query('COMMIT');
      } catch (e: any) {
        if (useTx) {
          try {
            await client.query('ROLLBACK');
          } catch {}
        }
        statements.push({
          sql: text.slice(0, 200),
          ok: false,
          command: '',
          rowCount: null,
          error: friendlyPgError(e)
        });
        return {
          statements,
          text: `失败(已回滚):${friendlyPgError(e)}`,
          latencyMs: Date.now() - started
        };
      }

      const affected = statements.reduce((s, x) => s + (x.rowCount ?? 0), 0);
      return {
        statements,
        text: `OK:${statements.length} 条语句 · 影响 ${affected} 行`,
        latencyMs: Date.now() - started
      };
    });
  }

  public async close(): Promise<void> {
    await Promise.all([...this.pools.values()].map((p) => p.end()));
    this.pools.clear();
  }
}

function formatRawType(r: {
  data_type: string;
  udt_name: string;
  character_maximum_length: number | null;
  numeric_precision: number | null;
  numeric_scale: number | null;
}): string {
  if (r.data_type === 'USER-DEFINED') return r.udt_name;
  if (r.data_type === 'character varying' && r.character_maximum_length) {
    return `varchar(${r.character_maximum_length})`;
  }
  if (r.data_type === 'numeric' && r.numeric_precision) {
    return r.numeric_scale ? `numeric(${r.numeric_precision},${r.numeric_scale})` : `numeric(${r.numeric_precision})`;
  }
  return r.data_type;
}

/** PG 错误 → 中文可读描述(带 SQLSTATE,便于排障) */
export function friendlyPgError(e: any): string {
  const code = e?.code as string | undefined;
  const msg = (e?.message || String(e)).slice(0, 200);
  switch (code) {
    case '42501':
      return `权限不足(42501):当前角色无权访问该对象——这是数据库层的边界,如需访问请更新权限清单并同步 ${msg}`;
    case '42P01':
      return `对象不存在(42P01):${msg}`;
    case '28P01':
      return `认证失败(28P01):数据库用户名或密码不正确 ${msg}`;
    case '3D000':
      return `数据库不存在(3D000):${msg}`;
    case '57014':
      return `语句超时(57014):超过 statement_timeout 限制 ${msg}`;
    case '23505':
      return `唯一约束冲突(23505):${msg}`;
    case '23503':
      return `外键约束冲突(23503):${msg}`;
    case '22P02':
      return `数据格式错误(22P02):${msg}`;
    case 'ECONNREFUSED':
      return '网络不可达:数据库主机拒绝连接(ECONNREFUSED)';
    case 'ETIMEDOUT':
      return '连接超时:数据库无响应';
    case 'ENOTFOUND':
      return '域名解析失败:数据库主机名无法解析(ENOTFOUND)';
    default:
      return code ? `数据库错误(${code}):${msg}` : `数据库错误:${msg}`;
  }
}
