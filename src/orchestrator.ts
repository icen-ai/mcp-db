import type { ConnectionConfig, DbmConfig, ScriptDef, UserConfig } from './config.js';
import { DbmError } from './errors.js';
import { PermissionEngine } from './permissions.js';
import { DirectPgProvider } from './pg-provider.js';
import { DirectMysqlProvider } from './mysql-provider.js';
import { McpProxyProvider } from './mcp-proxy-provider.js';
import { ScriptRegistry, renderTemplate } from './scripts.js';
import { analyzeSql } from './sql-guard.js';
import { AuditLog, defaultAuditPath, type AuditEntry, type AuditFilter } from './audit.js';
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
// 生产确认 → 爆炸半径护栏 → 按角色选池执行 → 核验 → 留痕。
// 「按角色选池」= 模式 A:连接本身的权限就是天花板,代码里没有提升通道。

const DEFAULT_MAX_AFFECTED = 1000;

export interface RunOptions {
  previewSql?: string;
  executeSql: string;
  /** 生产确认口令(requireConfirmForWrite 的连接上,写/DDL 必须携带) */
  confirm?: string;
  /** 爆炸半径放行(预演影响行数超 maxAffectedRows 时必须携带) */
  override?: boolean;
  /** 内部:脚本场景的审计上下文 */
  scriptId?: string;
}

export interface RunResult {
  env: string;
  role: string;
  /** true = 生产连接需要确认口令 */
  needConfirm?: boolean;
  /** true = 预演影响行数超过 maxAffectedRows,需 override 放行 */
  needOverride?: boolean;
  maxAffectedRows?: number;
  affectedBefore?: number;
  execute?: BatchResult;
  /** 执行后核验:重跑预演统计 */
  verify?: {
    affectedAfter: number;
    sampleRows: Record<string, any>[];
    sampleColumns: string[];
  } | null;
}

function createProvider(env: string, conn: ConnectionConfig): DatabaseProvider {
  switch (conn.type) {
    case 'postgres':
      return new DirectPgProvider(env, conn);
    case 'mysql':
      return new DirectMysqlProvider(env, conn);
    case 'mcp-proxy':
      return new McpProxyProvider(env, conn);
    default:
      throw new DbmError('CONFIG_INVALID', `连接 ${env} 的类型不支持:${(conn as any).type}`);
  }
}

export class Dbm {
  public readonly permissions: PermissionEngine;
  public readonly scripts: ScriptRegistry;
  private providers = new Map<string, DatabaseProvider>();

  constructor(
    public readonly config: DbmConfig,
    private audit: AuditLog,
    scripts: ScriptDef[] = []
  ) {
    this.permissions = new PermissionEngine(config);
    this.scripts = new ScriptRegistry(scripts);
    for (const [env, conn] of Object.entries(config.connections)) {
      this.providers.set(env, createProvider(env, conn));
    }
  }

  /** 从配置构建(库用法的主入口);审计路径优先级:显式 opts > config.audit.path > 默认 */
  public static fromConfig(config: DbmConfig, opts: { auditPath?: string; scripts?: ScriptDef[] } = {}): Dbm {
    return new Dbm(
      config,
      new AuditLog(opts.auditPath ?? config.audit?.path ?? defaultAuditPath()),
      opts.scripts ?? config.scripts ?? []
    );
  }

  public provider(env: string): DatabaseProvider {
    const p = this.providers.get(env);
    if (!p) {
      throw new DbmError('ENV_NOT_FOUND', `环境 "${env}" 不存在(可用:${[...this.providers.keys()].join(', ')})`);
    }
    return p;
  }

  /** 关闭全部底层资源(连接池/子进程) */
  public async close(): Promise<void> {
    await Promise.all([...this.providers.values()].map((p) => p.close?.()));
  }

  private async audited(entry: AuditEntry): Promise<void> {
    try {
      await this.audit.append(entry);
    } catch (e) {
      // 审计失败不让业务成功静默通过:写路径直接失败,读路径仅告警
      if (entry.action === 'run' || entry.action === 'run_script') throw e;
      console.error('[dbm] 审计写入失败(忽略):', e);
    }
  }

  /** 留痕完成后再抛出(审计先行,拒绝才有据可查) */
  private async deny(user: UserConfig, env: string, action: string, code: string, reason: string, sql?: string): Promise<never> {
    await this.audited({ ts: new Date().toISOString(), userId: user.id, env, action, ok: false, code, sql, detail: reason });
    throw new DbmError(code as any, reason);
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
    const res = await this.measure(env, sql, role);
    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env, action: 'preview', ok: true, role,
      sql, affected: res.affectedCount
    });
    return { affectedCount: res.affectedCount, sampleColumns: res.sampleColumns, sampleRows: res.sampleRows };
  }

  private async measure(env: string, sql: string, role: string) {
    const inner = sql.trim().replace(/;+\s*$/, '');
    const provider = this.provider(env);
    // ::int8 是 PG 方言;MySQL/proxy 用通用写法(mysql2 对 COUNT 已回数字)
    const countExpr = provider.dialect === 'postgres' ? 'COUNT(*)::int8' : 'COUNT(*)';
    const countRes = await provider.executeQuery(
      `SELECT ${countExpr} AS dbm_count FROM (${inner}) AS dbm_preview_t`,
      { maxRows: 1, role }
    );
    const sample = await provider.executeQuery(inner, { maxRows: 10, role });
    return {
      affectedCount: Number(countRes.rows[0]?.dbm_count ?? 0),
      sampleRows: sample.rows,
      sampleColumns: sample.columns
    };
  }

  private async safeMeasure(env: string, sql: string, role: string) {
    try {
      return await this.measure(env, sql, role);
    } catch (e) {
      console.error('[dbm] 预演失败(忽略):', e instanceof Error ? e.message : e);
      return null;
    }
  }

  /** 完整流程:预演 → 生产确认 → 爆炸半径护栏 → 执行 → 核验 → 留痕 */
  public async run(user: UserConfig, env: string, opts: RunOptions): Promise<RunResult> {
    const { executeSql, previewSql, confirm, override, scriptId } = opts;
    const analysis = analyzeSql(executeSql);
    const conn = this.config.connections[env];
    if (!conn) {
      throw new DbmError('ENV_NOT_FOUND', `环境 "${env}" 不存在(可用:${Object.keys(this.config.connections).join(', ')})`);
    }
    const action = scriptId ? 'run_script' : 'run';

    const check = this.permissions.check(user, env, analysis.maxOp);
    if (!check.allowed) {
      await this.deny(user, env, action, check.code!, check.reason!, executeSql);
    }
    const role = this.permissions.pickRole(user, env, analysis.maxOp)!;

    // 执行前预演(尽力而为,不阻塞执行)
    const before = previewSql ? await this.safeMeasure(env, previewSql, role) : null;

    // 生产确认闸:写/DDL 且连接要求确认时,必须携带口令
    const needsConfirm = conn.requireConfirmForWrite && (analysis.maxOp === 'write' || analysis.maxOp === 'ddl');
    if (needsConfirm && (confirm ?? '') !== (conn.confirmPhrase ?? '生产执行')) {
      await this.audited({
        ts: new Date().toISOString(), userId: user.id, env, action, ok: false,
        code: 'NEED_CONFIRM', role, sql: executeSql, scriptId,
        detail: `等待生产确认口令${confirm ? '(口令不匹配)' : ''}`
      });
      return {
        env, role, needConfirm: true,
        affectedBefore: before?.affectedCount,
        verify: before ? { affectedAfter: before.affectedCount, sampleRows: before.sampleRows, sampleColumns: before.sampleColumns } : null
      };
    }

    // 爆炸半径护栏:预演影响行数超过 maxAffectedRows 时需显式放行
    const maxAffected = conn.maxAffectedRows ?? DEFAULT_MAX_AFFECTED;
    const isMutation = analysis.maxOp === 'write' || analysis.maxOp === 'ddl';
    if (isMutation && before && before.affectedCount > maxAffected && !override) {
      await this.audited({
        ts: new Date().toISOString(), userId: user.id, env, action, ok: false,
        code: 'NEED_OVERRIDE', role, sql: executeSql, scriptId,
        detail: `预演影响 ${before.affectedCount} 行,超过护栏 ${maxAffected},等待 override 放行`
      });
      return {
        env, role, needOverride: true, maxAffectedRows: maxAffected,
        affectedBefore: before.affectedCount,
        verify: { affectedAfter: before.affectedCount, sampleRows: before.sampleRows, sampleColumns: before.sampleColumns }
      };
    }

    const execute = await this.provider(env).executeBatch(executeSql, { role });

    // 执行后核验(尽力而为)
    const after = previewSql ? await this.safeMeasure(env, previewSql, role) : null;

    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env, action, ok: execute.statements.every((s) => s.ok),
      role, sql: executeSql, scriptId, detail: execute.text,
      affected: execute.statements.reduce((s, x) => s + (x.rowCount ?? 0), 0)
    });

    return {
      env, role,
      affectedBefore: before?.affectedCount,
      execute,
      verify: after ? { affectedAfter: after.affectedCount, sampleRows: after.sampleRows, sampleColumns: after.sampleColumns } : null
    };
  }

  // ── 脚本注册表:受控操作,Agent 只传参数不碰 SQL 文本 ──────────────────────
  public listScripts(user: UserConfig, env?: string): ScriptDef[] {
    const envs = env ? [env] : Object.keys(this.config.connections);
    return this.scripts.list(env).filter((s) => {
      const allowed = s.envs.filter((e) => envs.includes(e));
      if (allowed.length === 0) return false;
      // 任一允许环境持有角色即可见
      return allowed.some((e) => this.permissions.userRolesForEnv(user, e).length > 0);
    });
  }

  public async runScript(
    user: UserConfig,
    env: string,
    scriptId: string,
    params: Record<string, any>,
    confirm?: string,
    override?: boolean
  ): Promise<RunResult> {
    const script = this.scripts.get(scriptId);
    if (!script.envs.includes(env)) {
      await this.deny(user, env, 'run_script', 'SCRIPT_ENV_NOT_ALLOWED', `脚本 "${scriptId}" 不允许在环境 ${env} 执行(允许:${script.envs.join(', ')})`);
    }
    const renderedPreview = renderTemplate(script.previewSql, params, script.params, script.id, { allowUnused: true });
    const renderedExecute = script.executeSql
      ? renderTemplate(script.executeSql, params, script.params, script.id)
      : undefined;

    if (!renderedExecute) {
      // 只读脚本:直接走 preview 通道
      const pv = await this.preview(user, env, renderedPreview);
      return {
        env, role: this.permissions.pickRole(user, env, 'read') ?? '',
        affectedBefore: pv.affectedCount,
        execute: { statements: [], text: '(只读脚本,无执行语句)', latencyMs: 0 },
        verify: { affectedAfter: pv.affectedCount, sampleRows: pv.sampleRows, sampleColumns: pv.sampleColumns }
      };
    }

    return this.run(user, env, {
      previewSql: renderedPreview,
      executeSql: renderedExecute,
      confirm,
      override,
      scriptId: script.id
    });
  }

  // ── 审计回查:自己的记录随时可查;查他人需 ddl 权限(admin 语义) ──────────
  public async auditQuery(user: UserConfig, filter: AuditFilter = {}): Promise<AuditEntry[]> {
    const isAdmin = Object.entries(user.roles).some(([env, roles]) =>
      roles.some((r) => this.permissions.opsForRole(env, r).has('ddl'))
    );
    if (filter.userId && filter.userId !== user.id && filter.userId !== '*' && !isAdmin) {
      await this.deny(user, '*', 'audit_query', 'DENIED_AUDIT_SCOPE', `用户 ${user.id} 无权查询他人的审计记录(需 ddl 级角色)`);
    }
    const userId = !filter.userId || filter.userId === '*' ? (isAdmin ? undefined : user.id) : filter.userId;
    const entries = this.audit.query({ ...filter, userId });
    await this.audited({
      ts: new Date().toISOString(), userId: user.id, env: filter.env ?? '*', action: 'audit_query', ok: true,
      detail: `${entries.length} 条`
    });
    return entries;
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
      // 逐角色探测:池凭证错误也能暴露出来(mcp-proxy 单角色 = 子进程连通性)
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
