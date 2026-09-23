import { describe, expect, test } from 'bun:test';
import { analyzeSql, classifyStatement, splitStatements } from '../src/sql-guard.js';

describe('splitStatements', () => {
  test('按分号拆分,忽略字符串内的分号', () => {
    const sql = `SELECT 1; SELECT 'a;b' AS s; SELECT 2`;
    expect(splitStatements(sql)).toEqual(['SELECT 1', `SELECT 'a;b' AS s`, 'SELECT 2']);
  });

  test('字符串内两个单引号转义不结束语句', () => {
    const sql = `SELECT 'it''s;fine'`;
    expect(splitStatements(sql)).toEqual([`SELECT 'it''s;fine'`]);
  });

  test('行注释里的分号不拆分', () => {
    const sql = `SELECT 1 -- comment; here\n; SELECT 2`;
    expect(splitStatements(sql)).toHaveLength(2);
  });

  test('块注释里的分号不拆分', () => {
    const sql = `SELECT /* ; */ 1; SELECT 2`;
    expect(splitStatements(sql)).toHaveLength(2);
  });

  test('dollar-quote 函数体里的分号不拆分', () => {
    const sql = `CREATE FUNCTION f() RETURNS int AS $x$ BEGIN RETURN 1; END $x$ LANGUAGE plpgsql`;
    expect(splitStatements(sql)).toHaveLength(1);
  });

  test('双引号标识符内的分号不拆分', () => {
    const sql = `SELECT 1 AS "we;ird"; SELECT 2`;
    expect(splitStatements(sql)).toHaveLength(2);
  });

  test('混合注入形态:SELECT 后藏 DROP', () => {
    const sql = `SELECT 1; DROP TABLE ty_project`;
    const parts = splitStatements(sql);
    expect(parts).toEqual(['SELECT 1', 'DROP TABLE ty_project']);
  });
});

describe('classifyStatement', () => {
  const cases: Array<[string, string]> = [
    ['SELECT * FROM t', 'read'],
    ['with x as (select 1) select * from x', 'read'],
    ['TABLE t', 'read'],
    ['VALUES (1), (2)', 'read'],
    ['SHOW work_mem', 'read'],
    ['EXPLAIN SELECT 1', 'read'],
    ['insert into t values (1)', 'write'],
    ['UPDATE t SET a = 1', 'write'],
    ['delete from t', 'write'],
    ['MERGE INTO t USING s ON (t.id = s.id) THEN UPDATE SET a = 2', 'write'],
    ["COPY t FROM '/tmp/x.csv'", 'write'],
    ['CALL do_something()', 'write'],
    ['create table x (id int)', 'ddl'],
    ['alter table x add column y int', 'ddl'],
    ['drop table x', 'ddl'],
    ['truncate table x', 'ddl'],
    ['grant select on t to u', 'ddl'],
    ['EXECUTE prepared_stmt', 'ddl'],
    ['SET LOCAL work_mem = \'64MB\'', 'meta'],
    ['BEGIN', 'meta'],
    ['COMMIT', 'meta']
  ];

  for (const [sql, expected] of cases) {
    test(`${sql.slice(0, 40)} → ${expected}`, () => {
      expect(classifyStatement(sql).op).toBe(expected);
    });
  }

  test('fail closed:未知语句按最高危处理', () => {
    expect(classifyStatement('GRANTLTO whatever').op).toBe('ddl');
  });

  test('前导注释/括号不影响分类', () => {
    expect(classifyStatement('/* hint */ (SELECT 1)').op).toBe('read');
    expect(classifyStatement('-- lead\n-- more\nDELETE FROM t').op).toBe('write');
  });
});

describe('analyzeSql', () => {
  test('maxOp 取最高危语句', () => {
    expect(analyzeSql('SELECT 1; UPDATE t SET a=1').maxOp).toBe('write');
    expect(analyzeSql('SELECT 1; DROP TABLE t').maxOp).toBe('ddl');
    expect(analyzeSql('SELECT 1').maxOp).toBe('read');
    expect(analyzeSql('BEGIN; SELECT 1').maxOp).toBe('read');
  });

  test('空串是 meta', () => {
    expect(analyzeSql('').maxOp).toBe('meta');
    expect(analyzeSql('   ').statements).toHaveLength(0);
  });
});
