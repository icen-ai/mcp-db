import { describe, expect, test } from 'bun:test';
import { renderTemplate, ScriptRegistry } from '../src/scripts.js';
import type { ScriptDef, ScriptParamDef } from '../src/config.js';
import { DbmError } from '../src/errors.js';

const defs: ScriptParamDef[] = [
  { name: 'code', type: 'string' },
  { name: 'region', type: 'string', required: false },
  { name: 'limit', type: 'number', required: false },
  { name: 'dry', type: 'boolean', required: false }
];

describe('renderTemplate(参数安全渲染)', () => {
  test('字符串参数以字面量进入 SQL,引号被转义', () => {
    const out = renderTemplate('SELECT * FROM t WHERE code = :code', { code: `P7'; DROP TABLE t;--` }, defs, 's1');
    expect(out).toBe(`SELECT * FROM t WHERE code = 'P7''; DROP TABLE t;--'`);
  });

  test('数字与布尔参数', () => {
    const out = renderTemplate('UPDATE t SET n = :limit, dry = :dry WHERE code = :code', { limit: 42, dry: true, code: 'P7' }, defs, 's1');
    expect(out).toBe(`UPDATE t SET n = 42, dry = TRUE WHERE code = 'P7'`);
  });

  test('非法数字被拒绝', () => {
    expect(() => renderTemplate('SELECT :limit', { limit: '1 OR 1=1' }, defs, 's1')).toThrow(DbmError);
  });

  test('非法布尔被拒绝', () => {
    expect(() => renderTemplate('SELECT :dry', { dry: 'yes please' }, defs, 's1')).toThrow(DbmError);
  });

  test('PG 类型转换 ::int 不被当作占位符', () => {
    const out = renderTemplate("SELECT '1'::int AS x, :code AS c", { code: 'P7' }, defs, 's1');
    expect(out).toBe("SELECT '1'::int AS x, 'P7' AS c");
  });

  test('未声明的占位符直接报错(fail closed)', () => {
    expect(() => renderTemplate('SELECT * FROM t WHERE x = :oops', {}, defs, 's1')).toThrow(DbmError);
  });

  test('必填参数缺失报错并列出缺失项', () => {
    expect(() => renderTemplate('SELECT :code', {}, defs, 's1')).toThrow(/code/);
  });

  test('传了未使用的参数报错(防拼写错误静默通过)', () => {
    expect(() => renderTemplate('SELECT :code', { code: 'P7', extra: 1 }, defs, 's1')).toThrow(/extra/);
  });

  test('可选参数未传时不报错', () => {
    const out = renderTemplate('SELECT :code', { code: 'P7' }, defs, 's1');
    expect(out).toBe(`SELECT 'P7'`);
  });
});

describe('ScriptRegistry', () => {
  const scripts: ScriptDef[] = [
    { id: 'fix_region', title: '修正区域', envs: ['dev'], params: defs, previewSql: 'SELECT 1', executeSql: 'UPDATE t SET region=:region' },
    { id: 'lookup', title: '查询', envs: ['dev', 'ga'], params: [], previewSql: 'SELECT 1' }
  ];
  const reg = new ScriptRegistry(scripts);

  test('按环境过滤', () => {
    expect(reg.list('ga').map((s) => s.id)).toEqual(['lookup']);
    expect(reg.list('dev').map((s) => s.id)).toEqual(['fix_region', 'lookup']);
  });

  test('不存在的脚本报 SCRIPT_NOT_FOUND', () => {
    expect(() => reg.get('nope')).toThrow(DbmError);
  });
});
