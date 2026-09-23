import { Client } from 'pg';
import type { ConnectionConfig, DbmConfig } from './config.js';
import { quoteIdent } from './config.js';
import type { SqlOp } from './types.js';

// ── GRANT 同步器:把权限清单物化为数据库原生授权 ──────────────────────────────
// 这是整套方案里唯一「新增的墙」:清单是唯一事实源,同步器做幂等 diff。
// 执行链路里的检查只是提前拒绝;本模块的产物才是不可穿透的边界。
//
// 模式 A(角色×连接池):GRANT 直接授予各池的登录用户(roles[role].user)。
// 清单里的 role 是池键;user 是数据库登录名。推荐两者同名,语义最直白。
//
// admin 凭证(roles.admin)是同步主体:其权限来自 DBA 身份(owner/superuser),
// 不在清单管理范畴——既不物化也不回收,否则 owner 隐式授权会破坏幂等性。

export type TablePrivilege = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';
export type SequencePrivilege = 'USAGE' | 'SELECT';
export type Privilege = TablePrivilege | SequencePrivilege;

const PRIVS_BY_OP: Record<Exclude<SqlOp, 'meta'>, TablePrivilege[]> = {
  read: ['SELECT'],
  write: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'],
  // ddl 不做表级物化:表结构变更属 admin 凭证直连范畴(同步本身就用 admin 连接)
  ddl: []
};

export interface SyncAction {
  kind: 'CREATE_ROLE' | 'ALTER_PASSWORD' | 'GRANT' | 'REVOKE';
  sql: string;
  detail: string;
}

export interface GrantPlan {
  env: string;
  actions: SyncAction[];
  warnings: string[];
}

/** 授权项键:"登录名|对象名" */
export type AclMap = Map<string, Set<Privilege>>;

export const aclKey = (login: string, obj: string) => `${login}|${obj}`;

/**
 * 目标授权:清单按「role → 登录名」映射后展开('*' 通配到 schema 实际表集)。
 * @param skipLogins 排除的登录名(admin 等同步主体)
 */
export function buildTargetAcl(config: DbmConfig, env: string, allTables: string[], skipLogins: Set<string> = new Set()): AclMap {
  const conn = config.connections[env];
  const target: AclMap = new Map();
  const tableSet = new Set(allTables);

  for (const g of config.grants) {
    if (g.env !== env) continue;
    const login = conn.roles[g.role]?.user ?? g.role;
    if (skipLogins.has(login)) continue;
    const tables = g.tables === '*' ? allTables : g.tables.filter((t) => tableSet.has(t));
    const privs = new Set<TablePrivilege>();
    for (const op of g.ops) {
      if (op === 'meta') continue;
      for (const p of PRIVS_BY_OP[op]) privs.add(p);
    }
    for (const t of tables) {
      const key = aclKey(login, t);
      const merged = target.get(key) ?? new Set<Privilege>();
      privs.forEach((p) => merged.add(p));
      target.set(key, merged);
    }
  }
  return target;
}

/** diff:current → target 需要执行的 GRANT/REVOKE(纯函数,可单测) */
export function diffAcl(
  current: AclMap,
  target: AclMap,
  schema: string,
  managedLogins: string[],
  objectType: 'TABLE' | 'SEQUENCE' = 'TABLE'
): SyncAction[] {
  const actions: SyncAction[] = [];
  const keys = new Set([...current.keys(), ...target.keys()]);

  for (const key of keys) {
    const [login, obj] = key.split('|');
    if (!managedLogins.includes(login)) continue; // 只管理自己的登录用户
    const cur = current.get(key) ?? new Set<Privilege>();
    const tgt = target.get(key) ?? new Set<Privilege>();

    const missing = [...tgt].filter((p) => !cur.has(p));
    const extra = [...cur].filter((p) => !tgt.has(p));

    const objRef = `${objectType} ${quoteIdent(schema)}.${quoteIdent(obj)}`;
    if (missing.length > 0) {
      actions.push({
        kind: 'GRANT',
        sql: `GRANT ${missing.join(', ')} ON ${objRef} TO ${quoteIdent(login)};`,
        detail: `${login} +${missing.join(',')} on ${schema}.${obj}${objectType === 'SEQUENCE' ? ' (sequence)' : ''}`
      });
    }
    if (extra.length > 0) {
      actions.push({
        kind: 'REVOKE',
        sql: `REVOKE ${extra.join(', ')} ON ${objRef} FROM ${quoteIdent(login)};`,
        detail: `${login} -${extra.join(',')} on ${schema}.${obj}${objectType === 'SEQUENCE' ? ' (sequence)' : ''}`
      });
    }
  }
  actions.sort((a, b) => a.detail.localeCompare(b.detail));
  return actions;
}

function escapePassword(pw: string): string {
  return "'" + pw.replace(/'/g, "''") + "'";
}

/**
 * 生成同步计划(不执行)。需要 admin 连接读取 pg_roles / information_schema。
 * @param opts.rotatePasswords 已存在的登录用户是否重设密码(默认否,避免误伤)
 */
export async function planGrants(
  admin: Client,
  config: DbmConfig,
  env: string,
  opts: { rotatePasswords?: boolean } = {}
): Promise<GrantPlan> {
  const conn = config.connections[env];
  const warnings: string[] = [];
  const actions: SyncAction[] = [];

  // 1. 登录用户存在性
  const managedLogins = [...new Set(Object.values(conn.roles).map((c) => c.user))];
  const existing = await admin.query<{ rolname: string }>(
    `SELECT rolname FROM pg_roles WHERE rolname = ANY($1::text[])`,
    [managedLogins]
  );
  const existingSet = new Set(existing.rows.map((r) => r.rolname));
  for (const login of managedLogins) {
    const cred = Object.values(conn.roles).find((c) => c.user === login)!;
    if (!existingSet.has(login)) {
      actions.push({
        kind: 'CREATE_ROLE',
        sql: `CREATE ROLE ${quoteIdent(login)} LOGIN PASSWORD ${escapePassword(cred.password)};`,
        detail: `创建登录用户 ${login}`
      });
    } else if (opts.rotatePasswords) {
      actions.push({
        kind: 'ALTER_PASSWORD',
        sql: `ALTER ROLE ${quoteIdent(login)} PASSWORD ${escapePassword(cred.password)};`,
        detail: `重设 ${login} 密码(rotatePasswords)`
      });
    }
  }

  // 2. schema 使用权(幂等,总是授予;USAGE 是任何表级权限的前置)
  for (const login of managedLogins) {
    actions.push({
      kind: 'GRANT',
      sql: `GRANT USAGE ON SCHEMA ${quoteIdent(conn.schema)} TO ${quoteIdent(login)};`,
      detail: `${login} USAGE on schema ${conn.schema}`
    });
  }

  // 3. 表级授权 diff(admin 登录除外:同步主体不归清单管)
  const adminLogin = conn.roles['admin']?.user;
  const tableManaged = managedLogins.filter((l) => l !== adminLogin);

  const tablesRes = await admin.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = $1 AND table_type IN ('BASE TABLE', 'VIEW')
     ORDER BY table_name`,
    [conn.schema]
  );
  const allTables = tablesRes.rows.map((r) => r.table_name);

  const aclRes = await admin.query<{ grantee: string; table_name: string; privilege_type: string }>(
    `SELECT grantee, table_name, privilege_type
     FROM information_schema.role_table_grants
     WHERE table_schema = $1`,
    [conn.schema]
  );
  const current: AclMap = new Map();
  for (const row of aclRes.rows) {
    if (!tableManaged.includes(row.grantee)) continue;
    const key = aclKey(row.grantee, row.table_name);
    const set = current.get(key) ?? new Set<Privilege>();
    set.add(row.privilege_type as Privilege);
    current.set(key, set);
  }

  const target = buildTargetAcl(config, env, allTables, new Set(adminLogin ? [adminLogin] : []));
  actions.push(...diffAcl(current, target, conn.schema, tableManaged, 'TABLE'));

  // 4. 序列授权:serial/identity 列的写入前置(nextval 需要 USAGE)
  //    目标:凡对表持有 INSERT 的登录名,对其附属序列授予 USAGE,SELECT
  const seqRes = await admin.query<{ table_name: string; seq_name: string }>(
    `SELECT t.relname AS table_name, s.relname AS seq_name
     FROM pg_depend d
     JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
     JOIN pg_class t ON t.oid = d.refobjid AND t.relkind = 'r'
     JOIN pg_namespace n ON n.oid = t.relnamespace
     WHERE d.classid = 'pg_class'::regclass
       AND d.refclassid = 'pg_class'::regclass
       AND d.deptype IN ('i', 'a')
       AND n.nspname = $1`,
    [conn.schema]
  );
  const seqsByTable = new Map<string, string[]>();
  for (const row of seqRes.rows) {
    const list = seqsByTable.get(row.table_name) ?? [];
    list.push(row.seq_name);
    seqsByTable.set(row.table_name, list);
  }

  const seqTarget: AclMap = new Map();
  for (const [key, privs] of target) {
    if (!privs.has('INSERT')) continue;
    const [login, table] = key.split('|');
    for (const seq of seqsByTable.get(table) ?? []) {
      const k2 = aclKey(login, seq);
      const merged = seqTarget.get(k2) ?? new Set<Privilege>();
      merged.add('USAGE');
      merged.add('SELECT');
      seqTarget.set(k2, merged);
    }
  }

  if (seqTarget.size > 0) {
    // information_schema.usage_privileges 只报 USAGE 不报序列 SELECT,幂等 diff 会失真;
    // 直接读 pg_class.relacl 并用 aclexplode 展开为 (grantee, privilege)。
    const seqAclRes = await admin.query<{ grantee: string; object_name: string; privilege_type: string }>(
      `SELECT grantee.rolname AS grantee, s.relname AS object_name, a.privilege_type
       FROM pg_class s
       JOIN pg_namespace n ON n.oid = s.relnamespace
       CROSS JOIN LATERAL aclexplode(COALESCE(s.relacl, acldefault('S', s.relowner))) AS a
       JOIN pg_roles grantee ON grantee.oid = a.grantee
       WHERE s.relkind = 'S' AND n.nspname = $1
         AND a.privilege_type IN ('USAGE', 'SELECT')`,
      [conn.schema]
    );
    const seqCurrent: AclMap = new Map();
    for (const row of seqAclRes.rows) {
      if (!tableManaged.includes(row.grantee)) continue;
      const key = aclKey(row.grantee, row.object_name);
      const set = seqCurrent.get(key) ?? new Set<Privilege>();
      set.add(row.privilege_type as Privilege);
      seqCurrent.set(key, set);
    }
    actions.push(...diffAcl(seqCurrent, seqTarget, conn.schema, tableManaged, 'SEQUENCE'));
  }

  // 5. 告警
  for (const g of config.grants) {
    if (g.env !== env || g.tables === '*') continue;
    for (const t of g.tables) {
      if (!allTables.includes(t)) warnings.push(`清单引用的表 ${conn.schema}.${t} 不存在(已跳过)`);
    }
  }
  for (const g of config.grants) {
    if (g.env === env && g.ops.includes('ddl')) {
      warnings.push(`角色 ${g.role} 的 ddl 权限不做表级物化,需通过 admin 凭证直连使用`);
    }
  }

  return { env, actions, warnings };
}

/** 在单个事务内执行计划;失败整体回滚 */
export async function applyGrants(admin: Client, plan: GrantPlan): Promise<{ applied: number }> {
  await admin.query('BEGIN');
  try {
    for (const a of plan.actions) {
      await admin.query(a.sql);
    }
    await admin.query('COMMIT');
    return { applied: plan.actions.length };
  } catch (e) {
    await admin.query('ROLLBACK');
    throw e;
  }
}

/** 同步用的 admin 连接(取连接配置中角色名为 admin 的凭证) */
export function adminClient(conn: ConnectionConfig): Client {
  const adminCred = conn.roles['admin'];
  if (!adminCred) {
    throw new Error(`连接 ${conn.database}@${conn.host} 未配置 admin 角色凭证,无法执行同步`);
  }
  return new Client({
    host: conn.host,
    port: conn.port,
    database: conn.database,
    user: adminCred.user,
    password: adminCred.password,
    statement_timeout: 15000
  });
}
