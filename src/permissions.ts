import type { DbmConfig, GrantRule, UserConfig } from './config.js';
import { opSeverity } from './sql-guard.js';
import type { SqlOp } from './types.js';

// ── 权限引擎(UX 层)────────────────────────────────────────────────────────
// 与 grant-sync 读取同一份清单:这里负责提前拒绝 + 友好报错;
// 真正的墙是 grant-sync 物化到数据库的 GRANT/REVOKE。
// 运行期不存在任何「提权通道」:角色→池映射在配置加载时固定。

export interface CheckResult {
  allowed: boolean;
  code?: 'DENIED_ENV' | 'DENIED_OP';
  reason?: string;
  /** 命中的用户角色 */
  roles: string[];
}

export class PermissionEngine {
  private rulesByEnv = new Map<string, GrantRule[]>();

  constructor(private config: DbmConfig) {
    for (const g of config.grants) {
      const list = this.rulesByEnv.get(g.env) ?? [];
      list.push(g);
      this.rulesByEnv.set(g.env, list);
    }
  }

  /** 用户在某环境持有的角色(∩ 配置中真实存在凭证的角色) */
  public userRolesForEnv(user: UserConfig, env: string): string[] {
    const conn = this.config.connections[env];
    if (!conn) return [];
    return (user.roles[env] ?? []).filter((r) => !!conn.roles[r]);
  }

  /** 角色在某环境被授予的操作类别集合 */
  public opsForRole(env: string, role: string): Set<SqlOp> {
    const ops = new Set<SqlOp>();
    for (const g of this.rulesByEnv.get(env) ?? []) {
      if (g.role === role) g.ops.forEach((o) => ops.add(o));
    }
    return ops;
  }

  /**
   * 选出执行角色:用户在该环境的角色中,取「能覆盖所需操作、且权限最小」者。
   * 平级按字典序,保证确定性。这就是「按角色选池」的落点。
   */
  public pickRole(user: UserConfig, env: string, requiredOp: SqlOp): string | null {
    const candidates = this.userRolesForEnv(user, env)
      .map((role) => ({ role, ops: this.opsForRole(env, role) }))
      .filter((c) => c.ops.has(requiredOp))
      .sort((a, b) => {
        const sa = Math.max(...[...a.ops].map(opSeverity), -1);
        const sb = Math.max(...[...b.ops].map(opSeverity), -1);
        return sa - sb || a.role.localeCompare(b.role);
      });
    return candidates.length > 0 ? candidates[0].role : null;
  }

  /** 请求期闸门:env 闸 + 语句类型闸 */
  public check(user: UserConfig, env: string, requiredOp: SqlOp): CheckResult {
    const roles = this.userRolesForEnv(user, env);
    if (roles.length === 0) {
      return {
        allowed: false,
        code: 'DENIED_ENV',
        reason: `用户 ${user.id} 在环境 ${env} 未持有任何角色`,
        roles
      };
    }
    if (requiredOp === 'meta') return { allowed: true, roles };
    const role = this.pickRole(user, env, requiredOp);
    if (!role) {
      const opLabel: Record<SqlOp, string> = { meta: '会话控制', read: '读取', write: '写入', ddl: 'DDL' };
      return {
        allowed: false,
        code: 'DENIED_OP',
        reason: `用户 ${user.id} 的角色(${roles.join(', ')})在 ${env} 无 ${opLabel[requiredOp]}权限`,
        roles
      };
    }
    return { allowed: true, roles: [role, ...roles.filter((r) => r !== role)] };
  }
}
