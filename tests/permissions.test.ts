import { describe, expect, test } from 'bun:test';
import { PermissionEngine } from '../src/permissions.js';
import type { DbmConfig, UserConfig } from '../src/config.js';

const config: DbmConfig = {
  connections: {
    dev: {
      type: 'postgres', host: 'h', port: 5432, database: 'd', schema: 'typlm',
      roles: {
        analyst: { user: 'plm_analyst', password: 'x' },
        ops: { user: 'plm_ops', password: 'x' }
      }
    },
    ga: {
      type: 'postgres', host: 'h2', port: 5432, database: 'd', schema: 'typlm',
      requireConfirmForWrite: true,
      roles: {
        analyst: { user: 'plm_analyst', password: 'x' },
        admin: { user: 'plm_admin', password: 'x' }
      }
    }
  },
  grants: [
    { env: 'dev', role: 'analyst', schema: 'typlm', tables: '*', ops: ['read'] },
    { env: 'dev', role: 'ops', schema: 'typlm', tables: ['ty_project'], ops: ['read', 'write'] },
    { env: 'ga', role: 'analyst', schema: 'typlm', tables: '*', ops: ['read'] },
    { env: 'ga', role: 'admin', schema: 'typlm', tables: '*', ops: ['read', 'write', 'ddl'] }
  ],
  users: []
};

const engine = new PermissionEngine(config);

const analystUser: UserConfig = {
  id: 'u_analyst',
  tokens: ['t-analyst-token-1'],
  roles: { dev: ['analyst'], ga: ['analyst'] }
};

const opsUser: UserConfig = {
  id: 'u_ops',
  tokens: ['t-ops-token-1'],
  roles: { dev: ['ops'] }
};

describe('PermissionEngine', () => {
  test('env 闸:没有角色的环境直接拒绝', () => {
    const r = engine.check(opsUser, 'ga', 'read');
    expect(r.allowed).toBe(false);
    expect(r.code).toBe('DENIED_ENV');
  });

  test('analyst 只读:read 放行,write/ddl 拒绝', () => {
    expect(engine.check(analystUser, 'dev', 'read').allowed).toBe(true);
    const w = engine.check(analystUser, 'dev', 'write');
    expect(w.allowed).toBe(false);
    expect(w.code).toBe('DENIED_OP');
    expect(engine.check(analystUser, 'dev', 'ddl').allowed).toBe(false);
  });

  test('ops 可写', () => {
    expect(engine.check(opsUser, 'dev', 'write').allowed).toBe(true);
    expect(engine.check(opsUser, 'dev', 'ddl').allowed).toBe(false);
  });

  test('meta 语句只要过了 env 闸就放行', () => {
    expect(engine.check(analystUser, 'dev', 'meta').allowed).toBe(true);
  });

  test('pickRole 选最小权限角色:同时持有 analyst+ops 时读走 analyst', () => {
    const dual: UserConfig = {
      id: 'u_dual', tokens: ['t-dual-token-1'],
      roles: { dev: ['analyst', 'ops'] }
    };
    expect(engine.pickRole(dual, 'dev', 'read')).toBe('analyst');
    expect(engine.pickRole(dual, 'dev', 'write')).toBe('ops');
  });

  test('清单外的角色(仅配置凭证)不获得任何操作', () => {
    const ghost: UserConfig = { id: 'u_ghost', tokens: ['t-ghost-token-1'], roles: { dev: ['nosuch'] } };
    // roles 校验在配置层拦截;这里测引擎侧:userRolesForEnv 过滤无凭证角色
    expect(engine.userRolesForEnv(ghost, 'dev')).toEqual([]);
  });
});
