// @icen.ai/dbm 公共 API
// 对内:库用法(编排器/Provider/同步器/权限引擎)
// 对外:bin(mcp-db serve)以 MCP server 暴露同一套流程

export * from './types.js';
export {
  DbmError,
  isDbmError,
  type DbmErrorCode
} from './errors.js';
export {
  loadConfig,
  resolveConfigPath,
  validateConfig,
  quoteIdent,
  type DbmConfig,
  type ConnectionConfig,
  type GrantRule,
  type RoleCredential,
  type UserConfig,
  type LoadedConfig
} from './config.js';
export { Authenticator } from './auth.js';
export { splitStatements, analyzeSql, classifyStatement, opSeverity, firstKeywordOf } from './sql-guard.js';
export { PermissionEngine, type CheckResult } from './permissions.js';
export {
  planGrants,
  applyGrants,
  adminClient,
  buildTargetAcl,
  diffAcl,
  aclKey,
  type GrantPlan,
  type SyncAction,
  type AclMap,
  type Privilege
} from './grant-sync.js';
export { DirectPgProvider, friendlyPgError } from './pg-provider.js';
export { Dbm, type RunOptions, type RunResult } from './orchestrator.js';
export { AuditLog, defaultAuditPath, type AuditEntry } from './audit.js';
export { serveMcp } from './mcp/server.js';
export { TOOLS, toolsListPayload, callTool, type ToolDef, type ToolContext } from './mcp/tools.js';
