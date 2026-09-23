import type { Dbm } from '../orchestrator.js';
import type { UserConfig } from '../config.js';
import { isDbmError } from '../errors.js';

// ── MCP 工具面:Agent 拿到的是「流程」,不是裸连接 ────────────────────────────
// 设计要点:
// 1. dbm_query 只读通道:语句类型闸 + 最小权限池,双保险
// 2. dbm_run 是唯一的写入口:预演 → needConfirm → confirm → 执行 → 核验
// 3. 所有结果同时给 structuredContent(结构化)与 content.text(JSON 串),
//    兼容只读文本的老客户端

export interface ToolContext {
  dbm: Dbm;
  user: UserConfig;
}

export interface ToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, any>;
  handler: (ctx: ToolContext, args: any) => Promise<any>;
}

function str(v: unknown, name: string): string {
  if (typeof v !== 'string' || !v) throw new Error(`参数 ${name} 必须是非空字符串`);
  return v;
}

export const TOOLS: ToolDef[] = [
  {
    name: 'dbm_whoami',
    description: '查看当前令牌对应的用户身份、各环境持有的角色与操作权限。排查权限问题时先调用它。',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    async handler(ctx) {
      const { user } = ctx;
      const envs: Record<string, { roles: string[]; ops: string[] }> = {};
      for (const [env, roles] of Object.entries(user.roles)) {
        envs[env] = {
          roles,
          ops: [...new Set(roles.flatMap((r) => [...ctx.dbm.permissions.opsForRole(env, r)]))]
        };
      }
      return { userId: user.id, name: user.name ?? user.id, envs };
    }
  },
  {
    name: 'dbm_health',
    description: '探测各环境数据库连接健康状态(逐角色探测,含延迟与错误原因)。',
    inputSchema: {
      type: 'object',
      properties: { env: { type: 'string', description: '环境 id;省略则探测全部' } },
      additionalProperties: false
    },
    async handler(ctx, args) {
      return ctx.dbm.health(ctx.user, typeof args?.env === 'string' && args.env ? args.env : undefined);
    }
  },
  {
    name: 'dbm_list_tables',
    description: '列出环境的表清单(含表注释)。只读。',
    inputSchema: {
      type: 'object',
      properties: {
        env: { type: 'string', description: '环境 id,如 dev / ga' },
        schema: { type: 'string', description: 'schema,默认取连接配置的业务 schema' }
      },
      required: ['env'],
      additionalProperties: false
    },
    async handler(ctx, args) {
      const tables = await ctx.dbm.listTables(ctx.user, str(args.env, 'env'), args.schema);
      return { count: tables.length, tables };
    }
  },
  {
    name: 'dbm_describe_table',
    description: '读取表的列元数据:物理类型、可空、主键、默认值、注释。只读。',
    inputSchema: {
      type: 'object',
      properties: {
        env: { type: 'string' },
        table: { type: 'string' },
        schema: { type: 'string' }
      },
      required: ['env', 'table'],
      additionalProperties: false
    },
    async handler(ctx, args) {
      const columns = await ctx.dbm.describeTable(ctx.user, str(args.env, 'env'), str(args.table, 'table'), args.schema);
      return { columns };
    }
  },
  {
    name: 'dbm_query',
    description:
      '执行只读 SQL(SELECT/WITH/VALUES/TABLE/SHOW/EXPLAIN)。返回列序、类型保真的行数据与截断标记。任何写语句都会被拒绝——写操作必须走 dbm_run。',
    inputSchema: {
      type: 'object',
      properties: {
        env: { type: 'string' },
        sql: { type: 'string', description: '单条只读 SQL' },
        maxRows: { type: 'number', description: '最大返回行数,默认 200,上限 2000' }
      },
      required: ['env', 'sql'],
      additionalProperties: false
    },
    async handler(ctx, args) {
      const res = await ctx.dbm.query(ctx.user, str(args.env, 'env'), str(args.sql, 'sql'), args.maxRows ?? 200);
      return { ...res, hint: res.truncated ? `结果超过上限已截断,可用更精确的 WHERE 或 maxRows 参数` : undefined };
    }
  },
  {
    name: 'dbm_preview',
    description: '预演一条 SQL:返回影响行数统计与前 10 行抽样。语句本身必须只读(通常是把写操作转成等价 SELECT)。',
    inputSchema: {
      type: 'object',
      properties: { env: { type: 'string' }, sql: { type: 'string' } },
      required: ['env', 'sql'],
      additionalProperties: false
    },
    async handler(ctx, args) {
      return ctx.dbm.preview(ctx.user, str(args.env, 'env'), str(args.sql, 'sql'));
    }
  },
  {
    name: 'dbm_run',
    description:
      '执行写操作,走完整流程:预演 → 生产确认(需要时)→ 执行 → 执行后核验。requireConfirmForWrite 的环境(生产)首次调用不带 confirm 会返回 needConfirm 与预演结果;用户确认后携带 confirm 口令(默认「生产执行」)再次调用才会真正执行。',
    inputSchema: {
      type: 'object',
      properties: {
        env: { type: 'string' },
        previewSql: { type: 'string', description: '预演/核验用的只读 SQL(强烈建议提供)' },
        executeSql: { type: 'string', description: '要执行的写/DDL SQL' },
        confirm: { type: 'string', description: '生产确认口令(仅生产环境需要)' }
      },
      required: ['env', 'executeSql'],
      additionalProperties: false
    },
    async handler(ctx, args) {
      return ctx.dbm.run(ctx.user, str(args.env, 'env'), {
        previewSql: typeof args.previewSql === 'string' && args.previewSql ? args.previewSql : undefined,
        executeSql: str(args.executeSql, 'executeSql'),
        confirm: typeof args.confirm === 'string' ? args.confirm : undefined
      });
    }
  }
];

/** 包装为 MCP tools/list 的返回结构 */
export function toolsListPayload() {
  return {
    tools: TOOLS.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema
    }))
  };
}

/** 执行一个工具调用,产出 MCP tools/call 的返回结构(含错误形态) */
export async function callTool(ctx: ToolContext, name: string, args: any): Promise<any> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) {
    return {
      isError: true,
      content: [{ type: 'text', text: `未知工具:${name}(可用:${TOOLS.map((t) => t.name).join(', ')})` }],
      structuredContent: { ok: false, code: 'UNKNOWN_TOOL', error: `未知工具:${name}` }
    };
  }
  try {
    const result = await tool.handler(ctx, args ?? {});
    return {
      content: [{ type: 'text', text: JSON.stringify(result, null, 1) }],
      structuredContent: result
    };
  } catch (e) {
    if (isDbmError(e)) {
      return {
        isError: true,
        content: [{ type: 'text', text: `[${e.code}] ${e.message}` }],
        structuredContent: { ok: false, code: e.code, error: e.message }
      };
    }
    const msg = e instanceof Error ? e.message : String(e);
    return {
      isError: true,
      content: [{ type: 'text', text: `[PROVIDER_ERROR] ${msg}` }],
      structuredContent: { ok: false, code: 'PROVIDER_ERROR', error: msg }
    };
  }
}
