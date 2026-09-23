import * as fs from 'fs';
import * as path from 'path';

// ── 审计留痕:JSONL 追加写 ───────────────────────────────────────────────────
// 每个入口动作(含被拒绝的)都留一条;SQL 截断防日志膨胀,token 永不入日志。

export interface AuditEntry {
  ts: string;
  userId: string;
  env: string;
  /** 动作名:query / preview / run / list_tables / describe_table / health */
  action: string;
  ok: boolean;
  code?: string;
  role?: string;
  /** SQL 前 2000 字符 */
  sql?: string;
  detail?: string;
  latencyMs?: number;
  affected?: number;
}

export class AuditLog {
  constructor(private filePath: string) {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
  }

  public async append(entry: AuditEntry): Promise<void> {
    const line = JSON.stringify({ ...entry, sql: entry.sql ? entry.sql.slice(0, 2000) : undefined }) + '\n';
    await fs.promises.appendFile(this.filePath, line, 'utf8');
  }
}

export function defaultAuditPath(configPath?: string): string {
  if (configPath) return path.join(path.dirname(configPath), 'audit.jsonl');
  return path.resolve('data', 'audit.jsonl');
}
