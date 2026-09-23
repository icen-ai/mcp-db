// 统一错误码:所有拒绝路径都以 code 呈现,便于上层(MCP/HTTP)原样透传并留痕
export type DbmErrorCode =
  | 'CONFIG_INVALID'
  | 'UNAUTHENTICATED'
  | 'ENV_NOT_FOUND'
  | 'DENIED_ENV'
  | 'DENIED_OP'
  | 'DENIED_NOT_READ'
  | 'NEED_CONFIRM'
  | 'PROVIDER_ERROR';

export class DbmError extends Error {
  public readonly code: DbmErrorCode;

  constructor(code: DbmErrorCode, message: string) {
    super(message);
    this.name = 'DbmError';
    this.code = code;
  }
}

export function isDbmError(e: unknown): e is DbmError {
  return e instanceof DbmError;
}
