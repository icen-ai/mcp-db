// 结构化契约:Provider 返回值一律为带类型的 JSON,禁止把显示格式当 API 用

/** 语句操作类别。meta = 会话/事务控制等无数据面影响的语句 */
export type SqlOp = 'read' | 'write' | 'ddl' | 'meta';

export interface TableMeta {
  schema: string;
  name: string;
  /** information_schema.table_type: BASE TABLE / VIEW / FOREIGN */
  type: string;
  comment: string | null;
}

export interface ColumnMeta {
  name: string;
  /** 归一化物理类型,如 varchar(255) / int8 / timestamptz */
  rawType: string;
  nullable: boolean;
  isPk: boolean;
  defaultVal: string | null;
  comment: string | null;
}

export interface QueryResult {
  /** 有序列名(与 rows 的 key 顺序一致) */
  columns: string[];
  rows: Record<string, any>[];
  rowCount: number;
  /** 命中 maxRows 截断标记 */
  truncated: boolean;
  latencyMs: number;
}

export interface StatementResult {
  sql: string;
  ok: boolean;
  command: string;
  rowCount: number | null;
  error?: string;
}

export interface BatchResult {
  statements: StatementResult[];
  /** 人读摘要,如 "3 statements · 12 rows affected" */
  text: string;
  latencyMs: number;
}

export interface HealthResult {
  ok: boolean;
  latencyMs: number;
  error?: string;
  role?: string;
}

export interface QueryOpts {
  maxRows?: number;
  role?: string;
}

export interface BatchOpts {
  role?: string;
  /** 默认 true:显式事务包裹,失败整体回滚 */
  transaction?: boolean;
}

/**
 * Provider = 查询通道。Client(展示出口,如 DBX 桌面联动)是另一个维度,
 * 以 optional capability 表达,不进通道接口本体。
 */
export interface DatabaseProvider {
  readonly env: string;
  readonly dialect: string;
  healthCheck(role?: string): Promise<HealthResult>;
  listTables(schema: string, role?: string): Promise<TableMeta[]>;
  describeTable(schema: string, table: string, role?: string): Promise<ColumnMeta[]>;
  executeQuery(sql: string, opts?: QueryOpts): Promise<QueryResult>;
  executeBatch(sql: string, opts?: BatchOpts): Promise<BatchResult>;
  /** 可选能力:把 SQL 推到某个桌面客户端展示(如 DBX execute_and_show) */
  showInClient?(sql: string, role?: string): Promise<void>;
}
