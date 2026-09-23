import type { SqlOp } from './types.js';

// ── SQL 语句拆分与分类(UX 护栏层)───────────────────────────────────────────
// 定位说明:这里的判断是「提前拒绝 + 友好报错 + 审计上下文」,不是防线。
// 防线在数据库:角色连接本身的 GRANT 范围。本层误判的后果是体验问题,
// 不是安全问题——因此宁可误杀(fail closed:未知语句一律按最高危处理)。

export interface StatementInfo {
  sql: string;
  op: SqlOp;
  /** 首关键字,如 SELECT / UPDATE / CREATE */
  kind: string;
}

export interface SqlAnalysis {
  statements: StatementInfo[];
  /** 全部语句中最高的操作类别(权限检查以它为准) */
  maxOp: SqlOp;
}

/** 词法边界内的分号才视为语句结束:'…'(含 '' 转义)、$$…$$、"--" 注释、块注释、双引号标识符 */
export function splitStatements(sql: string): string[] {
  const out: string[] = [];
  let cur = '';
  let i = 0;
  const n = sql.length;

  const state = { none: 0, single: 1, double: 2, dollar: 3, line: 4, block: 5 } as const;
  let st: (typeof state)[keyof typeof state] = state.none;
  let dollarTag = '';

  while (i < n) {
    const ch = sql[i];
    const next = i + 1 < n ? sql[i + 1] : '';

    switch (st) {
      case state.none:
        if (ch === "'") {
          st = state.single;
          cur += ch;
        } else if (ch === '"') {
          st = state.double;
          cur += ch;
        } else if (ch === '-' && next === '-') {
          st = state.line;
          cur += '--';
          i++;
        } else if (ch === '/' && next === '*') {
          st = state.block;
          cur += '/*';
          i++;
        } else if (ch === '$' && next === '$') {
          st = state.dollar;
          dollarTag = '$$';
          cur += '$$';
          i++;
        } else if (ch === '$') {
          // 带标签 dollar-quote:$tag$ … $tag$
          const m = /^\$[A-Za-z_][A-Za-z0-9_]*\$/.exec(sql.slice(i));
          if (m) {
            dollarTag = m[0];
            st = state.dollar;
            cur += m[0];
            i += m[0].length - 1;
          } else {
            cur += ch;
          }
        } else if (ch === ';') {
          const trimmed = cur.trim();
          if (trimmed) out.push(trimmed);
          cur = '';
        } else {
          cur += ch;
        }
        break;
      case state.single:
        cur += ch;
        if (ch === "'") {
          if (next === "'") {
            cur += next;
            i++;
          } else {
            st = state.none;
          }
        }
        break;
      case state.double:
        cur += ch;
        if (ch === '"') {
          if (next === '"') {
            cur += next;
            i++;
          } else {
            st = state.none;
          }
        }
        break;
      case state.dollar:
        if (sql.startsWith(dollarTag, i)) {
          cur += dollarTag;
          i += dollarTag.length - 1;
          st = state.none;
        } else {
          cur += ch;
        }
        break;
      case state.line:
        cur += ch;
        if (ch === '\n') st = state.none;
        break;
      case state.block:
        cur += ch;
        if (ch === '*' && next === '/') {
          cur += next;
          i++;
          st = state.none;
        }
        break;
    }
    i++;
  }

  const tail = cur.trim();
  if (tail) out.push(tail);
  return out;
}

/** 去掉前导注释/空白/括号后取首关键字 */
function leadingKeyword(stmt: string): string {
  let s = stmt;
  for (;;) {
    s = s.replace(/^\s+/, '');
    if (s.startsWith('--')) {
      const nl = s.indexOf('\n');
      s = nl === -1 ? '' : s.slice(nl + 1);
      continue;
    }
    if (s.startsWith('/*')) {
      const end = s.indexOf('*/');
      s = end === -1 ? '' : s.slice(end + 2);
      continue;
    }
    if (s.startsWith('(')) {
      s = s.slice(1);
      continue;
    }
    break;
  }
  const m = /^[A-Za-z_]+/.exec(s);
  return m ? m[0].toUpperCase() : '';
}

const OP_BY_KEYWORD: Record<string, SqlOp> = {
  // 读
  SELECT: 'read',
  WITH: 'read',
  TABLE: 'read',
  VALUES: 'read',
  SHOW: 'read',
  EXPLAIN: 'read',
  // 写
  INSERT: 'write',
  UPDATE: 'write',
  DELETE: 'write',
  MERGE: 'write',
  COPY: 'write',
  CALL: 'write',
  // DDL / 运维
  CREATE: 'ddl',
  ALTER: 'ddl',
  DROP: 'ddl',
  TRUNCATE: 'ddl',
  GRANT: 'ddl',
  REVOKE: 'ddl',
  COMMENT: 'ddl',
  REINDEX: 'ddl',
  CLUSTER: 'ddl',
  VACUUM: 'ddl',
  ANALYZE: 'ddl',
  REFRESH: 'ddl',
  // PREPARE 本身无害,但 EXECUTE 可执行任意已准备语句:一并按最高危处理
  PREPARE: 'ddl',
  EXECUTE: 'ddl',
  DEALLOCATE: 'ddl',
  // 会话/事务控制
  SET: 'meta',
  RESET: 'meta',
  BEGIN: 'meta',
  START: 'meta',
  COMMIT: 'meta',
  END: 'meta',
  ROLLBACK: 'meta',
  SAVEPOINT: 'meta',
  RELEASE: 'meta',
  ABORT: 'meta',
  DISCARD: 'meta',
  LISTEN: 'meta',
  UNLISTEN: 'meta',
  NOTIFY: 'meta',
  LOCK: 'meta',
  CHECKPOINT: 'meta',
  DECLARE: 'meta',
  CLOSE: 'meta',
  FETCH: 'read'
};

const OP_SEVERITY: Record<SqlOp, number> = { meta: 0, read: 1, write: 2, ddl: 3 };

export function opSeverity(op: SqlOp): number {
  return OP_SEVERITY[op];
}

export function classifyStatement(stmt: string): StatementInfo {
  const kind = leadingKeyword(stmt);
  // fail closed:无法识别的语句一律按 ddl(最高约束)处理,由角色体系裁决
  const op = OP_BY_KEYWORD[kind] ?? 'ddl';
  return { sql: stmt, op, kind: kind || '(empty)' };
}

export function analyzeSql(sql: string): SqlAnalysis {
  const statements = splitStatements(sql).map(classifyStatement);
  let maxOp: SqlOp = 'meta';
  for (const s of statements) {
    if (opSeverity(s.op) > opSeverity(maxOp)) maxOp = s.op;
  }
  return { statements, maxOp };
}

/** 首关键字(供 Provider 决定能否用子查询包裹来限流) */
export function firstKeywordOf(sql: string): string {
  const first = splitStatements(sql)[0] ?? '';
  return leadingKeyword(first);
}
