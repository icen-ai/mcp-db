import { describe, expect, test } from 'bun:test';
import { validateConfig } from '../src/config.js';
import { DbmError } from '../src/errors.js';

const valid = () => ({
  connections: {
    dev: {
      type: 'postgres', host: '192.168.112.205', port: 5432, database: 'typlm', schema: 'typlm',
      roles: { analyst: { user: 'plm_analyst', password: 'p' }, admin: { user: 'plm_admin', password: 'p' } }
    }
  },
  grants: [
    { env: 'dev', role: 'analyst', schema: 'typlm', tables: '*', ops: ['read'] },
    { env: 'dev', role: 'admin', schema: 'typlm', tables: '*', ops: ['read', 'write', 'ddl'] }
  ],
  users: [{ id: 'u_test', tokens: ['tok-12345678'], roles: { dev: ['analyst'] } }]
});

describe('validateConfig', () => {
  test('合法配置通过', () => {
    expect(() => validateConfig(valid(), 'test')).not.toThrow();
  });

  test('标识符白名单:连接名/角色名/schema/表名不接受特殊字符(堵死 SQL 注入原料)', () => {
    const bad = valid();
    (bad as any).connections['dev; DROP'] = bad.connections.dev;
    delete bad.connections.dev;
    expect(() => validateConfig(bad, 'test')).toThrow(DbmError);

    const bad2 = valid();
    bad2.grants[0].tables = ['ty_project; DROP TABLE x'];
    expect(() => validateConfig(bad2, 'test')).toThrow(DbmError);

    const bad3 = valid();
    (bad3 as any).connections.dev.roles['analyst--x'] = { user: 'u', password: 'p' };
    expect(() => validateConfig(bad3, 'test')).toThrow(DbmError);
  });

  test('grants 引用不存在的连接/缺凭证角色被拒', () => {
    const bad = valid();
    bad.grants[0].env = 'nosuch';
    expect(() => validateConfig(bad, 'test')).toThrow(DbmError);

    const bad2 = valid();
    bad2.users[0].roles.dev = ['ghost_role'];
    expect(() => validateConfig(bad2, 'test')).toThrow(DbmError);
  });

  test('ops 白名单', () => {
    const bad = valid();
    bad.grants[0].ops = ['read', 'superuser'];
    expect(() => validateConfig(bad, 'test')).toThrow(DbmError);
  });

  test('token 最短长度与重复检测', () => {
    const bad = valid();
    bad.users[0].tokens = ['short'];
    expect(() => validateConfig(bad, 'test')).toThrow(DbmError);

    const bad2 = valid();
    bad2.users[0].tokens = ['tok-12345678', 'tok-12345678'];
    expect(() => validateConfig(bad2, 'test')).toThrow(DbmError);
  });
});
