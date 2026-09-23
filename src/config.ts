import * as fs from 'fs';
import * as path from 'path';
import { DbmError } from './errors.js';
import type { SqlOp } from './types.js';

// ── 配置模型 ────────────────────────────────────────────────────────────────
// 密码等敏感值支持 ${ENV_NAME} 插值,配置文件本身可安全提交(占位符形态)

export interface RoleCredential {
  /** 池连接使用的数据库登录名 */
  user: string;
  password: string;
  /** 连接池上限,默认 4 */
  max?: number;
  /** 语句超时毫秒,默认 30000 */
  statementTimeoutMs?: number;
}

export interface ConnectionConfig {
  type: 'postgres';
  host: string;
  port: number;
  database: string;
  /** 业务默认 schema,如 typlm */
  schema: string;
  /** 生产类连接置 true:写/DDL 需要确认口令 */
  requireConfirmForWrite?: boolean;
  /** 确认口令,默认「生产执行」 */
  confirmPhrase?: string;
  ssl?: boolean;
  /** 各角色池凭证(键即角色名,须与 grants 清单一致) */
  roles: Record<string, RoleCredential>;
}

export interface GrantRule {
  env: string;
  role: string;
  schema: string;
  /** 表名数组;字符串 '*' 表示该 schema 全部表 */
  tables: string[] | '*';
  /** read → GRANT SELECT;write → +INSERT/UPDATE/DELETE;ddl 不做物化(仅 admin 直连范畴) */
  ops: SqlOp[];
}

export interface UserConfig {
  id: string;
  name?: string;
  tokens: string[];
  /** env → 角色列表 */
  roles: Record<string, string[]>;
}

export interface DbmConfig {
  connections: Record<string, ConnectionConfig>;
  grants: GrantRule[];
  users: UserConfig[];
  audit?: { path?: string };
}

// 标识符白名单:角色名/用户名/schema/表名只允许 [字母数字_],从源头堵死
// 通过配置注入 SQL 的可能(生成的 GRANT 语句不做参数化,必须管住原料)
const IDENT_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function isIdent(s: unknown): s is string {
  return typeof s === 'string' && IDENT_RE.test(s);
}

function interpolate(value: string): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, name: string) => {
    const v = process.env[name];
    if (v === undefined) {
      throw new DbmError('CONFIG_INVALID', `配置引用了未设置的环境变量 \${${name}}`);
    }
    return v;
  });
}

function walkInterpolate(node: any): any {
  if (typeof node === 'string') return interpolate(node);
  if (Array.isArray(node)) return node.map(walkInterpolate);
  if (node && typeof node === 'object') {
    const out: Record<string, any> = {};
    for (const [k, v] of Object.entries(node)) out[k] = walkInterpolate(v);
    return out;
  }
  return node;
}

export function validateConfig(raw: any, source: string): DbmConfig {
  const fail = (msg: string): never => {
    throw new DbmError('CONFIG_INVALID', `配置文件 ${source} 无效:${msg}`);
  };

  if (!raw || typeof raw !== 'object') fail('根必须是对象');
  const cfg = raw as DbmConfig;

  if (!cfg.connections || typeof cfg.connections !== 'object' || Object.keys(cfg.connections).length === 0) {
    fail('connections 不能为空');
  }
  for (const [env, conn] of Object.entries(cfg.connections)) {
    if (!isIdent(env)) fail(`连接名 "${env}" 不是合法标识符`);
    if (conn.type !== 'postgres') fail(`${env}: 当前仅支持 type=postgres`);
    if (!conn.host) fail(`${env}: 缺少 host`);
    if (typeof conn.port !== 'number') fail(`${env}: 缺少 port`);
    if (!isIdent(conn.schema)) fail(`${env}: schema 必须是合法标识符`);
    if (!conn.roles || Object.keys(conn.roles).length === 0) fail(`${env}: roles 不能为空`);
    for (const [role, cred] of Object.entries(conn.roles)) {
      if (!isIdent(role)) fail(`${env}.roles."${role}" 不是合法标识符`);
      if (!isIdent(cred?.user)) fail(`${env}.roles.${role}.user 不是合法标识符`);
      if (typeof cred?.password !== 'string' || !cred.password) fail(`${env}.roles.${role}.password 缺失`);
    }
  }

  if (!Array.isArray(cfg.grants)) fail('grants 必须是数组');
  for (const g of cfg.grants) {
    if (!cfg.connections[g.env]) fail(`grants 引用了不存在的连接 "${g.env}"`);
    if (!isIdent(g.role)) fail(`grants.role "${g.role}" 不是合法标识符`);
    if (!isIdent(g.schema)) fail(`grants.schema "${g.schema}" 不是合法标识符`);
    if (g.tables !== '*' && !(Array.isArray(g.tables) && g.tables.every(isIdent))) {
      fail(`grants(${g.env}/${g.role}) 的 tables 只能是 "*" 或标识符数组`);
    }
    const validOps: SqlOp[] = ['read', 'write', 'ddl'];
    if (!Array.isArray(g.ops) || !g.ops.every((o) => validOps.includes(o))) {
      fail(`grants(${g.env}/${g.role}) 的 ops 只能包含 ${validOps.join('/')}`);
    }
  }

  if (!Array.isArray(cfg.users) || cfg.users.length === 0) fail('users 不能为空');
  const seenTokens = new Set<string>();
  for (const u of cfg.users) {
    if (!isIdent(u.id)) fail(`users.id "${u.id}" 不是合法标识符`);
    if (!Array.isArray(u.tokens) || u.tokens.length === 0) fail(`${u.id}: tokens 不能为空`);
    for (const t of u.tokens) {
      if (typeof t !== 'string' || t.length < 8) fail(`${u.id}: token 长度至少 8`);
      if (seenTokens.has(t)) fail(`token 重复:${t.slice(0, 6)}…`);
      seenTokens.add(t);
    }
    if (!u.roles || typeof u.roles !== 'object') fail(`${u.id}: 缺少 roles`);
    for (const [env, roles] of Object.entries(u.roles)) {
      if (!cfg.connections[env]) fail(`${u.id}: 引用了不存在的连接 "${env}"`);
      if (!Array.isArray(roles) || roles.length === 0) fail(`${u.id}: ${env} 的角色列表为空`);
      for (const r of roles) {
        if (!isIdent(r)) fail(`${u.id}: 角色名 "${r}" 不是合法标识符`);
        if (!cfg.connections[env].roles[r]) {
          fail(`${u.id}: 角色 "${r}" 在连接 ${env} 中没有配置凭证`);
        }
      }
    }
  }

  return cfg;
}

export interface LoadedConfig {
  config: DbmConfig;
  path: string;
}

export function resolveConfigPath(explicit?: string): string {
  if (explicit) return path.resolve(explicit);
  const fromEnv = process.env.DBM_CONFIG;
  if (fromEnv) return path.resolve(fromEnv);
  return path.resolve('dbm.config.json');
}

export function loadConfig(explicit?: string): LoadedConfig {
  const p = resolveConfigPath(explicit);
  if (!fs.existsSync(p)) {
    throw new DbmError(
      'CONFIG_INVALID',
      `未找到配置文件 ${p}(可用 --config 或环境变量 DBM_CONFIG 指定;参考 dbm.example.json)`
    );
  }
  const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
  return { config: validateConfig(walkInterpolate(raw), p), path: p };
}

/** 双引号安全引用标识符(配置层已做白名单,这里是第二道保险) */
export function quoteIdent(name: string): string {
  return '"' + name.replace(/"/g, '""') + '"';
}
