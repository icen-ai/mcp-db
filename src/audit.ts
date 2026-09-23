import * as fs from 'fs';
import * as path from 'path';

// ── 审计留痕:JSONL 追加写 ───────────────────────────────────────────────────
// 每个入口动作(含被拒绝的)都留一条;SQL 截断防日志膨胀,token 永不入日志。

export interface AuditEntry {
  ts: string;
  userId: string;
  env: string;
  /** 动作名:query / preview / run / run_script / list_tables / describe_table / health / audit_query */
  action: string;
  ok: boolean;
  code?: string;
  role?: string;
  /** 脚本场景:脚本 id */
  scriptId?: string;
  /** SQL 前 2000 字符 */
  sql?: string;
  detail?: string;
  latencyMs?: number;
  affected?: number;
}

export interface AuditFilter {
  userId?: string;
  env?: string;
  action?: string;
  ok?: boolean;
  /** 取最近 N 条(倒序返回) */
  limit?: number;
}

export class AuditLog {
  constructor(private filePath: string) {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
  }

  public async append(entry: AuditEntry): Promise<void> {
    const line = JSON.stringify({ ...entry, sql: entry.sql ? entry.sql.slice(0, 2000) : undefined }) + '\n';
    await fs.promises.appendFile(this.filePath, line, 'utf8');
  }

  /** 过滤回查:返回按时间倒序的最近 N 条。文件规模内全量扫描,足够当前量级。 */
  public query(filter: AuditFilter = {}): AuditEntry[] {
    if (!fs.existsSync(this.filePath)) return [];
    const lines = fs.readFileSync(this.filePath, 'utf8').split('\n').filter(Boolean);
    const entries: AuditEntry[] = [];
    for (const line of lines) {
      try {
        const e = JSON.parse(line) as AuditEntry;
        if (filter.userId && e.userId !== filter.userId) continue;
        if (filter.env && e.env !== filter.env) continue;
        if (filter.action && e.action !== filter.action) continue;
        if (filter.ok !== undefined && e.ok !== filter.ok) continue;
        entries.push(e);
      } catch {}
    }
    entries.reverse();
    return entries.slice(0, filter.limit ?? 50);
  }
}

export function defaultAuditPath(configPath?: string): string {
  if (configPath) return path.join(path.dirname(configPath), 'audit.jsonl');
  return path.resolve('data', 'audit.jsonl');
}
