import type { DbmConfig, UserConfig } from './config.js';
import { DbmError } from './errors.js';
import { PermissionEngine } from './permissions.js';
import { DirectPgProvider } from './pg-provider.js';
import { analyzeSql } from './sql-guard.js';
import { AuditLog, defaultAuditPath, type AuditEntry } from './audit.js';
import type {
  BatchResult,
  ColumnMeta,
  DatabaseProvider,
  HealthResult,
  QueryResult,
  TableMeta
} from './types.js';

// ── 编排器:执行链路的唯一入口 ────────────────────────────────────────────────
// 每次请求:身份 → env 闸 → 语句分析 → 权限闸(拒绝则留痕+友好报错)→
// 生产确认 → 按角色选池执行 → 核验 → 留痕。
// 「按角色选池」= 模式 A:连接本身的权限就是天花板,代码里没有提升通道。

export interface RunOptions {
  previewSql?: string;
  executeSql: string;
  /** 生产确认口令(requireConfirmForWrite 的连接上,写/DDL 必须携带) */
  confirm?: string;
}

export interface RunResult {
  env: string;
  role: string;
  /** true = 需要先看预演结果并回传确认口令 */
  needConfirm?: boolean;
  affectedBefore?: number;
  execute?: BatchResult;
  /** 执行后核验:重跑预演统计 */
  verify?: {
    affectedAfter: number;
    sampleRows: Record<string, any>[];
    sampleColumns: string[];
  } | null;
}

export class Dbm {
  public readonly permissions: PermissionEngine;
  private providers = new Map<string, DirectPgProvider>();

  constructor(
    public readonly config: DbmConfig,
    private audit: AuditLog
  ) {
    this.permissions = new PermissionEngine(config);
    for (const [env, conn] of Object.entries(config.connections)) {
      this.providers.set(env, new DirectPgProvider(env, conn));
    }
  }

  /** 从配置构建(库用法的主入口) */
  public static fromConfig(config: DbmConfig, opts: { auditPath?: string } = {}): Dbm {
    return new Dbm(config, new AuditLog(opts.auditPath ?? defaultAuditPath()));
  }

  public provider(env: string): DatabaseProvider {
    const p = this.providers.get(env);
    if (!p) {
      throw new DbmError('ENV_NOT_FOUND', `环境 "${env}" 不存在(可用:${[...this.providers.keys()].join(', ')})`);
    }
    return p;
  }

  private async audited(entry: AuditEntry): Promise<void> {
    try {
      await this.audit.append(entry);
    } catch (e) {
      // 审计失败不让业务成功静默通过:写路径直接失败,读路径仅告警
      if (entry.action === 'run') throw e;
      console.error('[dbm] 审计写入失败(忽略):', e);
    }
  }

  /** 留痕完成后再抛出(审计先行,拒绝才有据可查) */
  private async deny(user: UserConfig, env: string, action: string, code: string, reason: string, sql?: string): Promise<never> {
    await this.audited({ ts: new Date().toISOString(), userId: user.id, env, action, ok: false, code, sql, detail: reason });
    throw new DbmError(code as any, reason);
  }

  /** 关闭全部连接池(进程退出前调用) */
  public async close(): Promise<void> {
    await Promise.all([...this.providers.values()].map((p) => p.close()));
  }

  // ── 只读通道:任何写/DDL 语句直接拒绝(建议绑 analyst 池,双保险) ──────────
  public async query(user: UserConfig, env: string, sql: string, maxRows = 200): Promise<QueryResult> {
    const analysis = analyzeSql(sql);
    const hasWrite = analysis.statements.some((s) => s.op === 'write' || s.op === 'ddl');
    if (hasWrite) {
      await this.deny(user, env, 'query', 'DENIED_NOT_READ', '查询通道仅允许只读语句;写操作请走 dbm_run(预演→确认→执行→核验)', sql);
    }
    const check = this.permissions.check(user, env, 'read');
    if (!check.allowed) {
      await this.deny(user, env, 'query', check.code!, check.reason!, sql);
    }
    const role = this.permissions.pickRole(user, env, 'read')!;
    try {
      const res = await this.provider(env).executeQuery(sql, { maxRows, role });
      await this.audited({
        ts: new Date().toISOString(), userId: user.id, env, action: 'query', ok: true, role,
        sql, latencyMs: res.latencyMs, affected: res.rowCount
      });
      return res;
    } catch (e: any) {
      await this.audited({
        ts: new Date().toISOString(), userId: user.id, env, action: 'query', ok: false, role,
        sql, detail: e.message
      });
      throw e;
    }
  }

  /** 预演:影响行数统计 + 抽样(只读) */
  public async preview(user: UserConfig, env: string, sql: string): Promise<{
    affectedCount: number;
    sampleColumns: string[];
    sampleRows: Record<string, any>[];
  }> {
    const analysis = analyzeSql(sql);
    const hasWrite = analysis.statements.some((s) => s.op === 'write' || s.op === 'ddl');
    if (hasWrite) {
      await this.deny(user, env, 'preview', 'DENIED_NOT_READ', '预演语句必须只读(影响行数统计 + 前 10 行抽样)', sql);
    }
    const check = this.permissions.check(user, env, 'read');
    if (!check.allowed) await this.deny(user, env, 'preview', check.code!, check.reason!, sql);
    const role = this.permissions.pickRole(user, env, 'read')!;
    const inner = sql.trim().replace(/;+\s*$/, '');
    const provider = this.provider(env);

    const countRes = await provider.executeQuery(
      `SELECT COUNT(*)::int8 AS dbm_count FROM (${inner}) AS dbm_preview_t`,
      { maxRows: 1, role }
    );
    const sample = await provider.executeQuery(inner, { maxRows: 10, role });
    const affectedCount = Number(countRes.rows[0]?.dbm_count ?? 0);
    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env, action: 'preview', ok: true, role,
      sql, affected: affectedCount
    });
    return { affectedCount, sampleColumns: sample.columns, sampleRows: sample.rows };
  }

  /** 完整流程:预演 → (生产确认) → 执行 → 核验 → 留痕 */
  public async run(user: UserConfig, env: string, opts: RunOptions): Promise<RunResult> {
    const { executeSql, previewSql, confirm } = opts;
    const analysis = analyzeSql(executeSql);
    const conn = this.config.connections[env];
    if (!conn) {
      throw new DbmError('ENV_NOT_FOUND', `环境 "${env}" 不存在(可用:${Object.keys(this.config.connections).join(', ')})`);
    }

    const check = this.permissions.check(user, env, analysis.maxOp);
    if (!check.allowed) {
      await this.deny(user, env, 'run', check.code!, check.reason!, executeSql);
    }
    const role = this.permissions.pickRole(user, env, analysis.maxOp)!;

    // 生产确认闸:写/DDL 且连接要求确认时,必须携带口令
    const needsConfirm = conn.requireConfirmForWrite && (analysis.maxOp === 'write' || analysis.maxOp === 'ddl');
    if (needsConfirm && (confirm ?? '') !== (conn.confirmPhrase ?? '生产执行')) {
      await this.audited({
        ts: new Date().toISOString(), userId: user.id, env, action: 'run', ok: false,
        code: 'NEED_CONFIRM', role, sql: executeSql,
        detail: `等待生产确认口令${confirm ? '(口令不匹配)' : ''}`
      });
      const pv = previewSql ? await this.safePreview(user, env, previewSql, role) : null;
      return {
        env, role, needConfirm: true,
        affectedBefore: pv?.affectedCount,
        verify: pv ? { affectedAfter: pv.affectedCount, sampleRows: pv.sampleRows, sampleColumns: pv.sampleColumns } : null
      };
    }

    // 执行前预演(尽力而为,不阻塞执行)
    const before = previewSql ? await this.safePreview(user, env, previewSql, role) : null;

    const execute = await this.provider(env).executeBatch(executeSql, { role });

    // 执行后核验(尽力而为)
    const after = previewSql ? await this.safePreview(user, env, previewSql, role) : null;

    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env, action: 'run', ok: execute.statements.every((s) => s.ok),
      role, sql: executeSql, detail: execute.text,
      affected: execute.statements.reduce((s, x) => s + (x.rowCount ?? 0), 0)
    });

    return {
      env, role,
      affectedBefore: before?.affectedCount,
      execute,
      verify: after ? { affectedAfter: after.affectedCount, sampleRows: after.sampleRows, sampleColumns: after.sampleColumns } : null
    };
  }

  private async safePreview(user: UserConfig, env: string, sql: string, role: string) {
    try {
      const inner = sql.trim().replace(/;+\s*$/, '');
      const provider = this.provider(env);
      const countRes = await provider.executeQuery(
        `SELECT COUNT(*)::int8 AS dbm_count FROM (${inner}) AS dbm_preview_t`,
        { maxRows: 1, role }
      );
      const sample = await provider.executeQuery(inner, { maxRows: 10, role });
      return {
        affectedCount: Number(countRes.rows[0]?.dbm_count ?? 0),
        sampleRows: sample.rows,
        sampleColumns: sample.columns
      };
    } catch (e) {
      console.error('[dbm] 预演失败(忽略):', e instanceof Error ? e.message : e);
      return null;
    }
  }

  // ── 元数据通道(只读权限即可) ────────────────────────────────────────────
  public async listTables(user: UserConfig, env: string, schema?: string): Promise<TableMeta[]> {
    const conn = this.config.connections[env];
    if (!conn) throw new DbmError('ENV_NOT_FOUND', `环境 "${env}" 不存在`);
    const check = this.permissions.check(user, env, 'read');
    if (!check.allowed) await this.deny(user, env, 'list_tables', check.code!, check.reason!);
    const role = this.permissions.pickRole(user, env, 'read')!;
    const res = await this.provider(env).listTables(schema ?? conn.schema, role);
    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env, action: 'list_tables', ok: true, role,
      affected: res.length
    });
    return res;
  }

  public async describeTable(user: UserConfig, env: string, table: string, schema?: string): Promise<ColumnMeta[]> {
    const conn = this.config.connections[env];
    if (!conn) throw new DbmError('ENV_NOT_FOUND', `环境 "${env}" 不存在`);
    const check = this.permissions.check(user, env, 'read');
    if (!check.allowed) await this.deny(user, env, 'describe_table', check.code!, check.reason!);
    const role = this.permissions.pickRole(user, env, 'read')!;
    const res = await this.provider(env).describeTable(schema ?? conn.schema, table, role);
    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env, action: 'describe_table', ok: true, role,
      detail: `${schema ?? conn.schema}.${table}`, affected: res.length
    });
    return res;
  }

  public async health(user: UserConfig, env?: string): Promise<Record<string, HealthResult>> {
    const envs = env ? [env] : Object.keys(this.config.connections);
    const out: Record<string, HealthResult> = {};
    for (const e of envs) {
      if (!this.config.connections[e]) throw new DbmError('ENV_NOT_FOUND', `环境 "${e}" 不存在`);
      const roles = Object.keys(this.config.connections[e].roles);
      // 逐角色探测:池凭证错误也能暴露出来
      for (const r of roles) {
        out[`${e}:${r}`] = await this.provider(e).healthCheck(r);
      }
    }
    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env: env ?? '*', action: 'health', ok: true
    });
    return out;
  }
}
