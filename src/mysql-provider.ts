import mysql, { type Pool } from 'mysql2/promise';
import type { MysqlConnectionConfig } from './config.js';
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

// ── MySQL 直连 Provider(角色 × 连接池)──────────────────────────────────────
// 与 DirectPgProvider 同一契约。注意:MySQL 的登录用户与授权由 DBA 预置
// (CREATE USER + GRANT);sync 仅支持 postgres——MySQL 的权限清单仍驱动
// UX 层检查,但「墙」是 DBA 手工建立的账号边界。

/** 可用子查询包裹限流的读语句形态(SHOW 等直接执行) */
const WRAPPABLE = new Set(['SELECT', 'WITH', 'TABLE', 'VALUES']);

export class DirectMysqlProvider implements DatabaseProvider {
  public readonly dialect = 'mysql';
  private pools = new Map<string, Pool>();

  constructor(
    public readonly env: string,
    private cfg: MysqlConnectionConfig
  ) {}

  private defaultRole(): string {
    return Object.keys(this.cfg.roles)[0];
  }

  public pool(role: string): Pool {
    const cred = this.cfg.roles[role];
    if (!cred?.user) {
      throw new Error(`角色 "${role}" 未在连接 ${this.env} 配置凭证(可用:${Object.keys(this.cfg.roles).join(', ')})`);
    }
    let pool = this.pools.get(role);
    if (!pool) {
      const opts: mysql.PoolOptions = {
        host: this.cfg.host,
        port: this.cfg.port,
        database: this.cfg.database,
        user: cred.user,
        password: cred.password,
        connectionLimit: cred.max ?? 4,
        // 批量多语句需要;单语句路径同样安全(语句分类已在编排层完成)
        multipleStatements: true,
        connectTimeout: 8000
      };
      if (this.cfg.ssl) opts.ssl = { rejectUnauthorized: false };
      pool = mysql.createPool(opts);
      this.pools.set(role, pool);
    }
    return pool;
  }

  public async healthCheck(role?: string): Promise<HealthResult> {
    const r = role ?? this.defaultRole();
    const started = Date.now();
    try {
      await this.pool(r).query('SELECT 1');
      return { ok: true, latencyMs: Date.now() - started, role: r };
    } catch (e: any) {
      return { ok: false, latencyMs: Date.now() - started, error: friendlyMysqlError(e), role: r };
    }
  }

  public async listTables(schema: string, role?: string): Promise<TableMeta[]> {
    const [rows] = await this.pool(role ?? this.defaultRole()).query<mysql.RowDataPacket[]>(
      `SELECT TABLE_NAME, TABLE_TYPE, TABLE_COMMENT, TABLE_ROWS, DATA_LENGTH + INDEX_LENGTH AS total_bytes
       FROM information_schema.TABLES
       WHERE TABLE_SCHEMA = ?
       ORDER BY TABLE_NAME`,
      [schema]
    );
    return rows.map((r) => ({
      schema,
      name: r.TABLE_NAME,
      type: r.TABLE_TYPE,
      comment: r.TABLE_COMMENT || null,
      estimatedRows: r.TABLE_ROWS !== null && r.TABLE_ROWS >= 0 ? Number(r.TABLE_ROWS) : null,
      sizeBytes: r.total_bytes !== null ? Number(r.total_bytes) : null
    }));
  }

  public async describeTable(schema: string, table: string, role?: string): Promise<ColumnMeta[]> {
    const pool = this.pool(role ?? this.defaultRole());
    const [cols] = await pool.query<mysql.RowDataPacket[]>(
      `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, COLUMN_KEY, COLUMN_COMMENT
       FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
       ORDER BY ORDINAL_POSITION`,
      [schema, table]
    );
    const [fks] = await pool.query<mysql.RowDataPacket[]>(
      `SELECT COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME
       FROM information_schema.KEY_COLUMN_USAGE
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND REFERENCED_TABLE_NAME IS NOT NULL`,
      [schema, table]
    );
    const fkMap = new Map(fks.map((r) => [r.COLUMN_NAME, { table: r.REFERENCED_TABLE_NAME, column: r.REFERENCED_COLUMN_NAME }]));

    return cols.map((r) => ({
      name: r.COLUMN_NAME,
      rawType: r.COLUMN_TYPE,
      nullable: r.IS_NULLABLE === 'YES',
      isPk: r.COLUMN_KEY === 'PRI',
      defaultVal: r.COLUMN_DEFAULT ?? null,
      comment: r.COLUMN_COMMENT || null,
      references: fkMap.get(r.COLUMN_NAME) ?? null
    }));
  }

  public async executeQuery(sql: string, opts: QueryOpts = {}): Promise<QueryResult> {
    const role = opts.role ?? this.defaultRole();
    const maxRows = Math.max(1, Math.min(opts.maxRows ?? 200, 2000));
    const inner = sql.trim().replace(/;+\s*$/, '');
    const started = Date.now();

    const wrappable = WRAPPABLE.has(firstKeywordOf(inner));
    const finalSql = wrappable ? `SELECT * FROM (${inner}) AS dbm_sub LIMIT ${maxRows + 1}` : inner;

    const timeout = this.cfg.roles[role]?.statementTimeoutMs ?? 30_000;
    const [result] = await this.pool(role).query({ sql: finalSql, timeout }).catch((e: any) => {
      throw new Error(friendlyMysqlError(e));
    });
    const rows = Array.isArray(result) ? (result as Record<string, any>[]) : [];
    const truncated = rows.length > maxRows;
    const sliced = truncated ? rows.slice(0, maxRows) : rows;
    // MySQL 空结果拿不到列名(协议限制),与 PG 的 fields 行为差异如实呈现
    const columns = sliced.length > 0 ? Object.keys(sliced[0]) : [];

    return { columns, rows: sliced, rowCount: sliced.length, truncated, latencyMs: Date.now() - started };
  }

  public async executeBatch(sql: string, opts: BatchOpts = {}): Promise<BatchResult> {
    const role = opts.role ?? this.defaultRole();
    const useTx = opts.transaction !== false;
    const text = sql.trim().replace(/;+\s*$/, '');
    const started = Date.now();
    const conn = await this.pool(role).getConnection();

    try {
      if (useTx) await conn.beginTransaction();
      const timeout = this.cfg.roles[role]?.statementTimeoutMs ?? 30_000;
      const [results] = await conn.query({ sql: text, timeout });
      const list = Array.isArray(results) ? results : [results];
      const statements = list.map((r: any) => ({
        sql: '',
        ok: true,
        command: 'OK',
        rowCount: typeof r?.affectedRows === 'number' ? r.affectedRows : null
      }));
      if (useTx) await conn.commit();
      const affected = statements.reduce((s, x) => s + (x.rowCount ?? 0), 0);
      return { statements, text: `OK:${statements.length} 条语句 · 影响 ${affected} 行`, latencyMs: Date.now() - started };
    } catch (e: any) {
      if (useTx) {
        try {
          await conn.rollback();
        } catch {}
      }
      const msg = friendlyMysqlError(e);
      return {
        statements: [{ sql: text.slice(0, 200), ok: false, command: '', rowCount: null, error: msg }],
        text: `失败(已回滚):${msg}`,
        latencyMs: Date.now() - started
      };
    } finally {
      conn.release();
    }
  }

  public async close(): Promise<void> {
    await Promise.all([...this.pools.values()].map((p) => p.end()));
    this.pools.clear();
  }
}

/** MySQL 错误 → 中文可读描述(带 errno) */
export function friendlyMysqlError(e: any): string {
  const code = e?.errno ?? e?.code;
  const msg = (e?.message || String(e)).slice(0, 200);
  switch (code) {
    case 1142:
    case 1143:
      return `权限不足(1142):当前用户无权访问该对象——数据库层边界,如需访问请联系 DBA 调整账号权限 ${msg}`;
    case 1044:
      return `权限不足(1044):无权访问该数据库 ${msg}`;
    case 1045:
      return `认证失败(1045):用户名或密码不正确 ${msg}`;
    case 1049:
      return `数据库不存在(1049):${msg}`;
    case 1146:
      return `表不存在(1146):${msg}`;
    case 1064:
      return `SQL 语法错误(1064):${msg}`;
    case 3024:
      return `查询超时(3024):超过 maxExecutionTime 限制 ${msg}`;
    case 'ECONNREFUSED':
      return '网络不可达:数据库主机拒绝连接(ECONNREFUSED)';
    case 'ETIMEDOUT':
      return '连接超时:数据库无响应';
    default:
      return code ? `数据库错误(${code}):${msg}` : `数据库错误:${msg}`;
  }
}
