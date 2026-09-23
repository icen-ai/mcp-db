import type { ScriptDef, ScriptParamDef } from './config.js';
import { DbmError } from './errors.js';

// ── 脚本渲染:参数只以字面量形式进入 SQL,杜绝拼接注入 ────────────────────────
// 占位符语法 :name;PG 类型转换 ::type 不受影响。
// 严格模式:SQL 里出现未声明的 :ident 直接报错(避免误替换/漏替换静默通过)。

/** 匹配 :name,但跳过 ::(类型转换)与 ':xxx'(已被字符串渲染覆盖的场景由转义保证) */
const PLACEHOLDER_RE = /(^|[^:]):([A-Za-z_][A-Za-z0-9_]*)/g;

export function renderTemplate(
  tpl: string,
  params: Record<string, any>,
  defs: ScriptParamDef[],
  scriptId: string,
  opts: { allowUnused?: boolean } = {}
): string {
  const byName = new Map(defs.map((d) => [d.name, d]));

  const missing = defs.filter((d) => d.required !== false && (params[d.name] === undefined || params[d.name] === null))
    .map((d) => d.name);
  if (missing.length > 0) {
    throw new DbmError('SCRIPT_INVALID_PARAMS', `脚本 ${scriptId} 缺少必填参数:${missing.join(', ')}`);
  }

  const unknownKeys = Object.keys(params).filter((k) => !byName.has(k));
  if (unknownKeys.length > 0) {
    throw new DbmError('SCRIPT_INVALID_PARAMS', `脚本 ${scriptId} 收到了未声明的参数:${unknownKeys.join(', ')}`);
  }

  const declared = new Set<string>();
  for (const m of tpl.matchAll(/::([A-Za-z_][A-Za-z0-9_]*)/g)) declared.add(m[1]); // ::type 不算占位符

  const seen = new Set<string>();
  const out = tpl.replace(PLACEHOLDER_RE, (full, prefix: string, name: string) => {
    if (!byName.has(name) && !declared.has(name)) {
      throw new DbmError('SCRIPT_INVALID_TEMPLATE', `脚本 ${scriptId} 的 SQL 含未声明占位符 :${name}`);
    }
    if (!byName.has(name)) return full; // ::type 转换的一部分
    seen.add(name);
    const def = byName.get(name)!;
    if (params[name] === undefined || params[name] === null) return prefix + 'NULL';
    return prefix + literal(params[name], def, scriptId, name);
  });

  const unused = defs.filter((d) => !seen.has(d.name) && params[d.name] !== undefined).map((d) => d.name);
  if (unused.length > 0 && !opts.allowUnused) {
    throw new DbmError('SCRIPT_INVALID_PARAMS', `脚本 ${scriptId} 收到了未使用的参数:${unused.join(', ')}`);
  }
  return out;
}

function literal(value: any, def: ScriptParamDef, scriptId: string, name: string): string {
  const type = def.type ?? 'string';
  if (type === 'number') {
    const n = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(n)) {
      throw new DbmError('SCRIPT_INVALID_PARAMS', `脚本 ${scriptId} 参数 ${name} 不是合法数字:${String(value)}`);
    }
    return String(n);
  }
  if (type === 'boolean') {
    if (typeof value === 'boolean') return value ? 'TRUE' : 'FALSE';
    const s = String(value).toLowerCase();
    if (s === 'true' || s === '1') return 'TRUE';
    if (s === 'false' || s === '0') return 'FALSE';
    throw new DbmError('SCRIPT_INVALID_PARAMS', `脚本 ${scriptId} 参数 ${name} 不是布尔值:${String(value)}`);
  }
  // string:单引号字面量,'' 转义——值里的任何内容(含注入载荷)都只是数据
  return "'" + String(value).replace(/'/g, "''") + "'";
}

export class ScriptRegistry {
  private byId = new Map<string, ScriptDef>();

  constructor(scripts: ScriptDef[]) {
    for (const s of scripts) this.byId.set(s.id, s);
  }

  public list(env?: string): ScriptDef[] {
    const all = [...this.byId.values()];
    return env ? all.filter((s) => s.envs.includes(env)) : all;
  }

  public get(id: string): ScriptDef {
    const s = this.byId.get(id);
    if (!s) {
      throw new DbmError('SCRIPT_NOT_FOUND', `脚本 "${id}" 不存在(可用:${this.list().map((x) => x.id).join(', ') || '无'})`);
    }
    return s;
  }
}
