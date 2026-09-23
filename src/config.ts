import * as fs from 'fs';
import * as path from 'path';
import { DbmError } from './errors.js';
import type { SqlOp } from './types.js';

// ── 配置模型 ────────────────────────────────────────────────────────────────
// 密码等敏感值支持 ${ENV_NAME} 插值,配置文件本身可安全提交(占位符形态)。
// 连接三态:postgres(直连+GRANT 同步)/ mysql(直连,凭证由 DBA 预置)/
//          mcp-proxy(桥接现成 MCP 数据源,如 dbhub/本项目的 mcp-db)

export interface RoleCredential {
  /** 池连接使用的数据库登录名(mcp-proxy 无凭证,可省略) */
  user?: string;
  password?: string;
  /** 连接池上限,默认 4 */
  max?: number;
  /** 语句超时毫秒,默认 30000 */
  statementTimeoutMs?: number;
}

interface ConnectionBase {
  /** 业务默认 schema,如 typlm */
  schema: string;
  /** 生产类连接置 true:写/DDL 需要 confirmPhrase 口令 */
  requireConfirmForWrite?: boolean;
  /** 确认口令,默认「生产执行」 */
  confirmPhrase?: string;
  /** 爆炸半径护栏:预演影响行数超过该值时需 override 放行,默认 1000 */
  maxAffectedRows?: number;
  /** 角色池凭证(键即角色名,须与 grants 清单一致) */
  roles: Record<string, RoleCredential>;
}

export interface PgConnectionConfig extends ConnectionBase {
  type: 'postgres';
  host: string;
  port: number;
  database: string;
  ssl?: boolean;
}

export interface MysqlConnectionConfig extends ConnectionBase {
  type: 'mysql';
  host: string;
  port: number;
  database: string;
  ssl?: boolean;
}

/** 上游 MCP 工具映射:args 值里的 $sql / $maxRows 会被实际值替换 */
export interface ProxyToolCall {
  name: string;
  args: Record<string, string>;
}

export interface McpProxyConnectionConfig extends ConnectionBase {
  type: 'mcp-proxy';
  /** 子进程命令,如 "bun" / "npx" / "dbx-mcp 路径" */
  command: string;
  args?: string[];
  env?: Record<string, string>;
  database: string;
  /** 上游方言(postgres/mysql 时 list/describe 走 information_schema 探测) */
  dialect?: 'postgres' | 'mysql';
  /** 上游返回解析:json(结构化文本)| markdown(表格文本兜底) */
  parseMode?: 'json' | 'markdown';
  tools: { query: ProxyToolCall; batch?: ProxyToolCall };
}

export type ConnectionConfig = PgConnectionConfig | MysqlConnectionConfig | McpProxyConnectionConfig;

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

export interface ScriptParamDef {
  name: string;
  description?: string;
  required?: boolean;
  type?: 'string' | 'number' | 'boolean';
}

/** 受控脚本:预审过的 previewSql/executeSql 对,Agent 只传参数不碰 SQL 文本 */
export interface ScriptDef {
  id: string;
  title: string;
  description?: string;
  /** 允许执行的环境 */
  envs: string[];
  params: ScriptParamDef[];
  /** 预演/核验 SQL(:name 占位符) */
  previewSql: string;
  /** 缺省为只读脚本 */
  executeSql?: string;
}

export interface DbmConfig {
  connections: Record<string, ConnectionConfig>;
  grants: GrantRule[];
  users: UserConfig[];
  /** 脚本注册表(或用 scriptsFile 外置) */
  scripts?: ScriptDef[];
  /** 外置脚本文件路径(相对配置文件目录) */
  scriptsFile?: string;
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

function validateConnection(env: string, conn: any, fail: (m: string) => never): ConnectionConfig {
  if (!isIdent(env)) fail(`连接名 "${env}" 不是合法标识符`);
  if (!conn || typeof conn !== 'object') fail(`${env}: 连接必须是对象`);
  if (!isIdent(conn.schema)) fail(`${env}: schema 必须是合法标识符`);
  if (!conn.roles || typeof conn.roles !== 'object' || Object.keys(conn.roles).length === 0) {
    fail(`${env}: roles 不能为空`);
  }
  const needsCred = conn.type !== 'mcp-proxy';
  for (const [role, cred] of Object.entries<RoleCredential>(conn.roles)) {
    if (!isIdent(role)) fail(`${env}.roles."${role}" 不是合法标识符`);
    if (!isIdent(cred?.user)) {
      if (needsCred) fail(`${env}.roles.${role}.user 不是合法标识符`);
    } else if (needsCred && (typeof cred.password !== 'string' || !cred.password)) {
      fail(`${env}.roles.${role}.password 缺失`);
    }
  }

  switch (conn.type) {
    case 'postgres':
    case 'mysql': {
      if (!conn.host) fail(`${env}: 缺少 host`);
      if (typeof conn.port !== 'number') fail(`${env}: 缺少 port`);
      if (!conn.database) fail(`${env}: 缺少 database`);
      return conn as PgConnectionConfig | MysqlConnectionConfig;
    }
    case 'mcp-proxy': {
      if (!conn.command) fail(`${env}: mcp-proxy 缺少 command`);
      if (!conn.database) fail(`${env}: mcp-proxy 缺少 database(展示用标识)`);
      if (!conn.tools?.query?.name) fail(`${env}: mcp-proxy 缺少 tools.query.name`);
      if (conn.tools?.query?.args && typeof conn.tools.query.args !== 'object') {
        fail(`${env}: tools.query.args 必须是对象`);
      }
      if (conn.parseMode && !['json', 'markdown'].includes(conn.parseMode)) {
        fail(`${env}: parseMode 只能是 json | markdown`);
      }
      return conn as McpProxyConnectionConfig;
    }
    default:
      fail(`${env}: 未知连接 type "${conn.type}"(支持 postgres / mysql / mcp-proxy)`);
  }
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
  const connections: Record<string, ConnectionConfig> = {};
  for (const [env, conn] of Object.entries<any>(cfg.connections)) {
    connections[env] = validateConnection(env, conn, fail);
  }
  cfg.connections = connections;

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

  if (cfg.scripts) {
    if (!Array.isArray(cfg.scripts)) fail('scripts 必须是数组(或用 scriptsFile 外置)');
    for (const s of cfg.scripts) validateScript(s, cfg, fail);
  }
  if (cfg.scriptsFile && typeof cfg.scriptsFile !== 'string') fail('scriptsFile 必须是字符串路径');

  return cfg;
}

export function validateScript(s: any, cfg: DbmConfig, fail: (m: string) => never): ScriptDef {
  if (!isIdent(s?.id)) fail(`scripts.id "${s?.id}" 不是合法标识符`);
  if (!s?.title) fail(`脚本 ${s.id}: 缺少 title`);
  if (!Array.isArray(s?.envs) || s.envs.length === 0) fail(`脚本 ${s.id}: envs 不能为空`);
  for (const e of s.envs) {
    if (!isIdent(e)) fail(`脚本 ${s.id}: 环境 "${e}" 不是合法标识符`);
    if (!cfg.connections[e]) fail(`脚本 ${s.id}: 引用了不存在的连接 "${e}"`);
  }
  if (!s.previewSql || typeof s.previewSql !== 'string') fail(`脚本 ${s.id}: 缺少 previewSql`);
  if (s.executeSql !== undefined && typeof s.executeSql !== 'string') fail(`脚本 ${s.id}: executeSql 必须是字符串`);
  const seen = new Set<string>();
  for (const p of s.params ?? []) {
    if (!isIdent(p?.name)) fail(`脚本 ${s.id}: 参数名 "${p?.name}" 不是合法标识符`);
    if (seen.has(p.name)) fail(`脚本 ${s.id}: 参数 ${p.name} 重复`);
    seen.add(p.name);
    if (p.type && !['string', 'number', 'boolean'].includes(p.type)) {
      fail(`脚本 ${s.id}: 参数 ${p.name} 的 type 只能是 string/number/boolean`);
    }
  }
  return s as ScriptDef;
}

export interface LoadedConfig {
  config: DbmConfig;
  path: string;
  scripts: ScriptDef[];
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
  const config = validateConfig(walkInterpolate(raw), p);

  // 脚本注册表:scriptsFile 外置优先,否则用内联 scripts
  let scripts: ScriptDef[] = config.scripts ?? [];
  if (config.scriptsFile) {
    const sp = path.resolve(path.dirname(p), config.scriptsFile);
    if (!fs.existsSync(sp)) {
      throw new DbmError('CONFIG_INVALID', `scriptsFile 指向的文件不存在:${sp}`);
    }
    const fail = (m: string): never => {
      throw new DbmError('CONFIG_INVALID', `脚本文件 ${sp} 无效:${m}`);
    };
    const rawScripts = JSON.parse(fs.readFileSync(sp, 'utf8'));
    if (!Array.isArray(rawScripts)) fail('根必须是脚本数组');
    scripts = rawScripts.map((s: any) => validateScript(s, config, fail));
  }

  const ids = new Set<string>();
  for (const s of scripts) {
    if (ids.has(s.id)) throw new DbmError('CONFIG_INVALID', `脚本 id 重复:${s.id}`);
    ids.add(s.id);
  }
  return { config, path: p, scripts };
}

/** 双引号安全引用标识符(配置层已做白名单,这里是第二道保险) */
export function quoteIdent(name: string): string {
  return '"' + name.replace(/"/g, '""') + '"';
}
