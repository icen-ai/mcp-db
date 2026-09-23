import { describe, expect, test } from 'bun:test';
import { aclKey, buildTargetAcl, diffAcl, type AclMap, type Privilege } from '../src/grant-sync.js';
import type { DbmConfig } from '../src/config.js';

const set = (...ps: Privilege[]): Set<Privilege> => new Set(ps);

const config: DbmConfig = {
  connections: {
    dev: {
      type: 'postgres', host: 'h', port: 5432, database: 'd', schema: 'typlm',
      roles: {
        analyst: { user: 'plm_analyst', password: 'x' },
        ops: { user: 'plm_ops', password: 'x' }
      }
    }
  },
  grants: [
    { env: 'dev', role: 'analyst', schema: 'typlm', tables: ['ty_project', 'dim_customer'], ops: ['read'] },
    { env: 'dev', role: 'ops', schema: 'typlm', tables: ['ty_project'], ops: ['read', 'write'] }
  ],
  users: [{ id: 'u', tokens: ['t-token-1234'], roles: { dev: ['analyst'] } }]
};

describe('buildTargetAcl', () => {
  test('清单展开为 登录名|表 → 权限集合;role 映射到 user', () => {
    const target = buildTargetAcl(config, 'dev', ['ty_project', 'dim_customer', 'ty_secret']);
    expect(target.get(aclKey('plm_analyst', 'ty_project'))).toEqual(set('SELECT'));
    expect(target.get(aclKey('plm_ops', 'ty_project'))).toEqual(set('SELECT', 'INSERT', 'UPDATE', 'DELETE'));
    expect(target.has(aclKey('plm_ops', 'dim_customer'))).toBe(false);
    expect(target.has(aclKey('plm_analyst', 'ty_secret'))).toBe(false);
  });

  test('通配 "*" 展开为 schema 全部表', () => {
    const cfg: DbmConfig = {
      ...config,
      grants: [{ env: 'dev', role: 'analyst', schema: 'typlm', tables: '*', ops: ['read'] }]
    };
    const target = buildTargetAcl(cfg, 'dev', ['a', 'b', 'c']);
    expect(target.size).toBe(3);
  });
});

describe('diffAcl', () => {
  const managed = ['plm_analyst', 'plm_ops'];

  test('新增授权:目标有、现线无 → GRANT', () => {
    const current: AclMap = new Map();
    const target: AclMap = new Map([[aclKey('plm_analyst', 't'), set('SELECT')]]);
    const actions = diffAcl(current, target, 'typlm', managed);
    const grants = actions.filter((a) => a.kind === 'GRANT');
    expect(grants).toHaveLength(1);
    expect(grants[0].sql).toBe('GRANT SELECT ON TABLE "typlm"."t" TO "plm_analyst";');
  });

  test('回收:现线有、目标无 → REVOKE', () => {
    const current: AclMap = new Map([[aclKey('plm_ops', 't'), set('SELECT', 'DELETE')]]);
    const target: AclMap = new Map([[aclKey('plm_ops', 't'), set('SELECT')]]);
    const actions = diffAcl(current, target, 'typlm', managed);
    expect(actions).toHaveLength(1);
    expect(actions[0].kind).toBe('REVOKE');
    expect(actions[0].sql).toBe('REVOKE DELETE ON TABLE "typlm"."t" FROM "plm_ops";');
  });

  test('表从清单移除 → REVOKE 全部剩余权限', () => {
    const current: AclMap = new Map([[aclKey('plm_ops', 'old_t'), set('SELECT', 'UPDATE')]]);
    const target: AclMap = new Map();
    const actions = diffAcl(current, target, 'typlm', managed);
    expect(actions).toHaveLength(1);
    expect(actions[0].sql).toBe('REVOKE SELECT, UPDATE ON TABLE "typlm"."old_t" FROM "plm_ops";');
  });

  test('一致则零变更;非托管角色的 ACL 不碰', () => {
    const same: AclMap = new Map([[aclKey('plm_analyst', 't'), set('SELECT')]]);
    expect(diffAcl(same, same, 'typlm', managed)).toHaveLength(0);

    const foreign: AclMap = new Map([[aclKey('someone_else', 't'), set('SELECT')]]);
    expect(diffAcl(foreign, new Map(), 'typlm', managed)).toHaveLength(0);
  });

  test('多条授权合并去重后生成', () => {
    const current: AclMap = new Map();
    const target: AclMap = new Map([
      [aclKey('plm_analyst', 'b'), set('SELECT')],
      [aclKey('plm_ops', 'a'), set('SELECT', 'INSERT')]
    ]);
    const actions = diffAcl(current, target, 'typlm', managed);
    expect(actions.filter((a) => a.kind === 'GRANT')).toHaveLength(2);
    for (const a of actions) expect(a.sql).toMatch(/^GRANT [A-Z, ]+ ON TABLE "typlm"\."[ab]" TO "plm_(analyst|ops)";$/);
  });
});

describe('buildTargetAcl · 表模式通配', () => {
  const cfgOf = (tables: any) => ({
    ...config,
    grants: [{ env: 'dev', role: 'ops', schema: 'typlm', tables, ops: ['read', 'write'] }]
  });
  const ALL = ['ty_project', 'ty_secret', 'act_hi_actinst', 'dim_customer'];

  test('前缀模式 ty_* 只匹配 ty_ 开头的表', () => {
    const target = buildTargetAcl(cfgOf(['ty_*']), 'dev', ALL);
    const tables = [...target.keys()].map((k) => k.split('|')[1]).sort();
    expect(tables).toEqual(['ty_project', 'ty_secret']);
  });

  test('后缀模式 *_actinst', () => {
    const target = buildTargetAcl(cfgOf(['*_actinst']), 'dev', ALL);
    expect([...target.keys()].map((k) => k.split('|')[1])).toEqual(['act_hi_actinst']);
  });

  test('混排:精确名 + 模式,去重合并', () => {
    const target = buildTargetAcl(cfgOf(['dim_customer', 'ty_*']), 'dev', ALL);
    const tables = [...target.keys()].map((k) => k.split('|')[1]).sort();
    expect(tables).toEqual(['dim_customer', 'ty_project', 'ty_secret']);
  });

  test('模式零匹配 → 空授权(告警由 planGrants 产生)', () => {
    const target = buildTargetAcl(cfgOf(['zzz_*']), 'dev', ALL);
    expect(target.size).toBe(0);
  });
});
