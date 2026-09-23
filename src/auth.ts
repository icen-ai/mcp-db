import type { UserConfig } from './config.js';
import { DbmError } from './errors.js';

// token → 用户。token 只在配置文件/环境变量中,不落审计日志。
// 建议占位符 + ${ENV} 注入,轮换即改环境变量。

export class Authenticator {
  private byToken = new Map<string, UserConfig>();

  constructor(users: UserConfig[]) {
    for (const u of users) {
      for (const t of u.tokens) this.byToken.set(t, u);
    }
  }

  public resolve(token: string | undefined | null): UserConfig {
    if (!token) {
      throw new DbmError(
        'UNAUTHENTICATED',
        '缺少访问令牌:请以环境变量 DBM_TOKEN 提供(用户 tokens 定义在配置文件 users 段)'
      );
    }
    const user = this.byToken.get(token);
    if (!user) {
      throw new DbmError('UNAUTHENTICATED', '令牌无效或已撤销');
    }
    return user;
  }
}
