// 端到端验证:docker 起真实 PostgreSQL + MySQL → 同步权限清单 → 逐项断言安全属性。
// 这是「二次分配不被穿透」的实证:越权请求由数据库以 42501/1142 拒绝,
// 而不是靠中间层 if 挡(中间层只负责提前给出友好报错)。
// 另含:mcp-proxy 回环(用本项目自己的 mcp-db serve 作为上游)。
import { execSync } from 'child_process';
import { Client } from 'pg';
import mysql from 'mysql2/promise';
import * as path from 'path';
import * as fs from 'fs';
import { loadConfig, validateConfig } from '../src/config.js';
import { adminClient, applyGrants, planGrants } from '../src/grant-sync.js';
import { Dbm } from '../src/orchestrator.js';
import { isDbmError } from '../src/errors.js';

const PG_CONTAINER = 'dbm-e2e';
const MY_CONTAINER = 'dbm-e2e-mysql';
const PG_PORT = 55432;
const MY_PORT = 55433;
const ROOT = path.resolve(import.meta.dir, '..');
const FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'dbm.test.json');
const OUTER_AUDIT = path.resolve('data', 'audit-e2e.jsonl');

function sh(cmd: string): string {
  return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).toString();
}

const results: Array<{ name: string; pass: boolean; note: string }> = [];
function check(name: string, pass: boolean, note = '') {
  results.push({ name, pass, note });
  console.log(`  ${pass ? '✓' : '✗'} ${name}${note ? ` — ${note}` : ''}`);
}

async function waitForPg(host: string, port: number, user: string, password: string, db: string, timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const c = new Client({ host, port, user, password, database: db, connectionTimeoutMillis: 2000 });
    try {
      await c.connect();
      await c.query('SELECT 1');
      await c.end();
      return;
    } catch {
      try {
        await c.end();
      } catch {}
      if (Date.now() > deadline) throw new Error('PostgreSQL 就绪超时');
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}

async function waitForMysql(timeoutMs: number) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const conn = await mysql.createConnection({
        host: '127.0.0.1', port: MY_PORT, user: 'root', password: 'mysql_root_pw', database: 'typlm'
      });
      await conn.query('SELECT 1');
      await conn.end();
      return;
    } catch {
      if (Date.now() > deadline) throw new Error('MySQL 就绪超时');
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

async function main() {
  console.log('== 准备:并行启动 PostgreSQL 与 MySQL 容器 ==');
  for (const c of [PG_CONTAINER, MY_CONTAINER]) {
    try {
      execSync(`docker rm -f ${c}`, { stdio: 'ignore' });
    } catch {}
  }
  sh(`docker run -d --name ${PG_CONTAINER} -e POSTGRES_USER=dbm_admin -e POSTGRES_PASSWORD=admin_pw -e POSTGRES_DB=typlm -p ${PG_PORT}:5432 postgres:16-alpine`);
  sh(`docker run -d --name ${MY_CONTAINER} -e MYSQL_ROOT_PASSWORD=mysql_root_pw -e MYSQL_DATABASE=typlm -p ${MY_PORT}:3306 mysql:8`);
  await waitForPg('127.0.0.1', PG_PORT, 'dbm_admin', 'admin_pw', 'typlm', 90_000);

  // PG 种子:授权表 + 未授权表 + 外键(元数据断言用)+ ANALYZE(估算行数)
  const seed = new Client({ host: '127.0.0.1', port: PG_PORT, user: 'dbm_admin', password: 'admin_pw', database: 'typlm' });
  await seed.connect();
  await seed.query(`CREATE SCHEMA IF NOT EXISTS typlm`);
  await seed.query(`CREATE TABLE typlm.ty_project (id serial PRIMARY KEY, project_code text, region text)`);
  await seed.query(`CREATE TABLE typlm.ty_secret (id serial PRIMARY KEY, token text, project_id int REFERENCES typlm.ty_project(id))`);
  await seed.query(`INSERT INTO typlm.ty_project (project_code, region) VALUES ('P7-260001', '华东'), ('LE-260002', '华南')`);
  await seed.query(`INSERT INTO typlm.ty_secret (token, project_id) VALUES ('sk-should-not-leak', 1)`);
  await seed.query(`ANALYZE typlm.ty_project`);
  await seed.query(`ANALYZE typlm.ty_secret`);
  await seed.end();
  console.log('  PG 种子就绪(ty_project ×2 含 FK 子表 ty_secret)');

  const loaded = loadConfig(FIXTURE);
  const config = loaded.config;

  // 外层 e2e 扩展:MySQL 直连 + mcp-proxy 回环(上游 = 本项目 mcp-db serve)
  ;(config.connections as any).mydev = {
    type: 'mysql', host: '127.0.0.1', port: MY_PORT, database: 'typlm', schema: 'typlm',
    roles: {
      analyst: { user: 'plm_analyst', password: 'analyst_pw' },
      ops: { user: 'plm_ops', password: 'ops_pw' }
    }
  };
  ;(config.connections as any).hub = {
    type: 'mcp-proxy', command: 'bun',
    args: [path.join(ROOT, 'src', 'cli.ts'), 'serve', '--config', FIXTURE],
    env: { DBM_TOKEN: 'test-token-analyst-0001' },
    database: 'loopback', schema: 'typlm', dialect: 'postgres', parseMode: 'json',
    tools: { query: { name: 'dbm_query', args: { env: 'dev', sql: '$sql', maxRows: '$maxRows' } } },
    roles: { default: {} }
  };
  config.grants.push(
    { env: 'mydev', role: 'analyst', schema: 'typlm', tables: ['ty_project'], ops: ['read'] },
    { env: 'mydev', role: 'ops', schema: 'typlm', tables: ['ty_project', 'ty_secret'], ops: ['read', 'write'] },
    { env: 'hub', role: 'default', schema: 'typlm', tables: '*', ops: ['read'] }
  );
  config.users[0].roles.mydev = ['analyst'];
  config.users[1].roles.mydev = ['ops'];
  config.users[0].roles.hub = ['default'];
  config.audit = { path: OUTER_AUDIT };

  const dbm = Dbm.fromConfig(config, { scripts: loaded.scripts, auditPath: OUTER_AUDIT });
  const analyst = config.users.find((u) => u.id === 'u_analyst')!;
  const ops = config.users.find((u) => u.id === 'u_ops')!;
  const admin = config.users.find((u) => u.id === 'u_admin')!;

  // ── 同步前:analyst 凭证尚不存在 ──
  console.log('\n== 同步前 ==');
  try {
    await dbm.query(analyst, 'dev', 'SELECT * FROM typlm.ty_project');
    check('同步前 analyst 无法查询(登录用户不存在)', false, '意外成功');
  } catch (e: any) {
    check('同步前 analyst 无法查询(登录用户不存在)', true, (e.message ?? '').slice(0, 50));
  }

  // ── 权限清单物化 ──
  console.log('\n== 同步:清单 → 原生 GRANT/REVOKE ==');
  const adminConn = adminClient(config.connections.dev as any);
  await adminConn.connect();
  const plan = await planGrants(adminConn, config, 'dev');
  for (const a of plan.actions) console.log(`    [${a.kind}] ${a.detail}`);
  const { applied } = await applyGrants(adminConn, plan);
  await adminConn.end();
  check('同步完成', applied === plan.actions.length, `应用 ${applied} 条授权语句`);

  const again = adminClient(config.connections.dev as any);
  await again.connect();
  const plan2 = await planGrants(again, config, 'dev');
  await again.end();
  const objChanges = plan2.actions.filter((a) => a.sql.includes(' ON TABLE ') || a.sql.includes(' ON SEQUENCE '));
  check('二次同步幂等', objChanges.length === 0, objChanges.map((a) => a.detail).join('; ') || '无对象级变更');

  // ── 授权范围内通行 + 元数据加深 ──
  console.log('\n== 授权范围内 ==');
  const proj = await dbm.query(analyst, 'dev', 'SELECT id, project_code, region FROM typlm.ty_project');
  check('analyst 查询授权表 ty_project', proj.rows.length === 2 && proj.columns.length === 3,
    `${proj.rows.length} 行,列序 [${proj.columns.join(',')}]`);

  const typed = await dbm.query(analyst, 'dev', 'SELECT id FROM typlm.ty_project WHERE id = 1');
  check('类型保真(id 为 number 而非字符串)', typeof typed.rows[0]?.id === 'number', `typeof id = ${typeof typed.rows[0]?.id}`);

  const tables = await dbm.listTables(analyst, 'dev');
  const tp = tables.find((t) => t.name === 'ty_project');
  check('表清单含估算行数(ANALYZE 后)', tp != null && (tp.estimatedRows ?? 0) >= 2, `estimatedRows=${tp?.estimatedRows}`);

  const secretCols = await dbm.describeTable(ops, 'dev', 'ty_secret');
  const fkCol = secretCols.find((c) => c.name === 'project_id');
  check('列元数据含外键指向', fkCol?.references?.table === 'ty_project' && fkCol.references.column === 'id',
    `project_id → ${fkCol?.references?.table}.${fkCol?.references?.column}`);

  // ── 越权路径(墙在数据库)──
  console.log('\n== 越权路径(墙在数据库)==');
  try {
    await dbm.query(analyst, 'dev', 'SELECT * FROM typlm.ty_secret');
    check('analyst 读未授权表 ty_secret → 42501 拒绝', false, '意外成功:敏感数据泄露');
  } catch (e: any) {
    check('analyst 读未授权表 ty_secret → 42501 拒绝', (e.message ?? '').includes('42501'), (e.message ?? '').slice(0, 60));
  }

  try {
    await dbm.run(analyst, 'dev', { executeSql: `INSERT INTO typlm.ty_project (project_code) VALUES ('HACK-1')` });
    check('analyst 写授权表被拒', false, '意外成功');
  } catch (e: any) {
    check('analyst 写授权表被拒', isDbmError(e) && e.code === 'DENIED_OP', e.code ?? '');
  }

  try {
    await dbm.query(analyst, 'dev', 'SELECT 1; DROP TABLE typlm.ty_secret');
    check('「SELECT 1; DROP TABLE」混合语句被拒', false, '意外成功');
  } catch (e: any) {
    check('「SELECT 1; DROP TABLE」混合语句被拒', true, (e.message ?? '').slice(0, 50));
  }

  const rawClient = new Client({ host: '127.0.0.1', port: PG_PORT, user: 'plm_analyst', password: 'analyst_pw', database: 'typlm' });
  await rawClient.connect();
  try {
    await rawClient.query('SELECT * FROM typlm.ty_secret');
    check('绕过中间层直连(偷到 analyst 凭证)读 ty_secret → 42501', false, '意外成功');
  } catch (e: any) {
    check('绕过中间层直连(偷到 analyst 凭证)读 ty_secret → 42501', e.code === '42501', `SQLSTATE ${e.code}`);
  }
  await rawClient.end();

  // ── 写流程:预演 → 执行 → 核验;爆炸半径护栏 ──
  console.log('\n== 写流程与护栏 ==');
  const writeRes = await dbm.run(ops, 'dev', {
    previewSql: `SELECT COUNT(*) AS c FROM typlm.ty_project WHERE region = '西南'`,
    executeSql: `INSERT INTO typlm.ty_project (project_code, region) VALUES ('P7-260099', '西南')`
  });
  check('ops 执行写入', writeRes.execute?.statements.every((s) => s.ok) === true, writeRes.execute?.text);
  check('执行后核验生效', writeRes.verify?.affectedAfter === 1, `核验计数 ${writeRes.verify?.affectedAfter}`);

  // 护栏:dev maxAffectedRows=1,批量 UPDATE 预演计数 3 → needOverride
  const bulk = await dbm.run(ops, 'dev', {
    previewSql: 'SELECT id FROM typlm.ty_project WHERE region IS NOT NULL',
    executeSql: "UPDATE typlm.ty_project SET region = '批量'"
  });
  check('爆炸半径护栏:影响 3 行超阈值 → needOverride 拦截',
    bulk.needOverride === true && bulk.execute === undefined, `阈值 ${bulk.maxAffectedRows},预演 ${bulk.affectedBefore}`);

  const bulkOk = await dbm.run(ops, 'dev', {
    previewSql: 'SELECT id FROM typlm.ty_project WHERE region IS NOT NULL',
    executeSql: "UPDATE typlm.ty_project SET region = '批量'",
    override: true
  });
  check('携带 override 放行后执行', bulkOk.execute?.statements[0].ok === true, bulkOk.execute?.text);

  // ga 确认闸
  const gaNoConfirm = await dbm.run(admin, 'ga', {
    previewSql: 'SELECT COUNT(*) AS c FROM typlm.ty_secret',
    executeSql: 'DELETE FROM typlm.ty_secret WHERE id > 100'
  });
  check('生产连接无口令 → needConfirm 拦截', gaNoConfirm.needConfirm === true && gaNoConfirm.execute === undefined);

  const gaConfirm = await dbm.run(admin, 'ga', {
    previewSql: 'SELECT COUNT(*) AS c FROM typlm.ty_secret',
    executeSql: 'DELETE FROM typlm.ty_secret WHERE id > 100',
    confirm: '生产执行'
  });
  check('携带口令 → 执行通过', gaConfirm.needConfirm === undefined && gaConfirm.execute?.statements[0].ok === true);

  try {
    await dbm.run(ops, 'dev', { executeSql: 'CREATE TABLE typlm.hack (id int)' });
    check('ops 执行 DDL → 中间层 DENIED_OP', false, '意外成功');
  } catch (e: any) {
    check('ops 执行 DDL → 中间层 DENIED_OP', isDbmError(e) && e.code === 'DENIED_OP', e.code ?? '');
  }

  // ── 脚本注册表 ──
  console.log('\n== 脚本注册表(受控操作)==');
  const scriptsVisible = dbm.listScripts(ops, 'dev');
  check('脚本可见性(env 过滤)', scriptsVisible.some((s) => s.id === 'fix_region') && scriptsVisible.some((s) => s.id === 'count_by_region'),
    `${scriptsVisible.length} 个`);

  const readonlyScript = await dbm.runScript(analyst, 'dev', 'count_by_region', {});
  check('只读脚本走 preview 通道', readonlyScript.execute?.text.includes('只读脚本') === true,
    `统计行 ${readonlyScript.verify?.affectedAfter}`);

  // 注入载荷作为参数值:只能变成字面量
  const payload = `x'; DROP TABLE typlm.ty_project;--`;
  const scripted = await dbm.runScript(ops, 'dev', 'fix_region', { code: 'P7-260001', region: payload });
  check('脚本执行(参数含注入载荷)', scripted.execute?.statements[0].ok === true);
  const afterInj = await dbm.query(ops, 'dev', `SELECT region FROM typlm.ty_project WHERE project_code = 'P7-260001'`);
  check('注入载荷被字面量化,表完好', afterInj.rows[0]?.region === payload, `region=${String(afterInj.rows[0]?.region).slice(0, 30)}…`);

  try {
    await dbm.runScript(ops, 'dev', 'fix_region', { code: 'P7-260001', region: 'ok', extra: 1 });
    check('未声明参数被拒', false, '意外成功');
  } catch (e: any) {
    check('未声明参数被拒', isDbmError(e) && e.code === 'SCRIPT_INVALID_PARAMS', e.code ?? '');
  }

  try {
    await dbm.runScript(ops, 'ga', 'fix_region', { code: 'X', region: 'y' });
    check('脚本环境白名单生效', false, '意外成功');
  } catch (e: any) {
    check('脚本环境白名单生效', isDbmError(e) && e.code === 'SCRIPT_ENV_NOT_ALLOWED', e.code ?? '');
  }

  // ── 审计回查 ──
  console.log('\n== 审计回查 ==');
  const own = await dbm.auditQuery(analyst, { limit: 200 });
  check('用户可查自己的留痕', own.length > 0 && own.every((x) => x.userId === 'u_analyst'), `${own.length} 条`);

  try {
    await dbm.auditQuery(analyst, { userId: 'u_ops' });
    check('查他人留痕被拒(无 ddl 角色)', false, '意外成功');
  } catch (e: any) {
    check('查他人留痕被拒(无 ddl 角色)', isDbmError(e) && e.code === 'DENIED_AUDIT_SCOPE', e.code ?? '');
  }

  const adminView = await dbm.auditQuery(admin, { userId: 'u_ops', limit: 200 });
  check('ddl 角色可查他人留痕', adminView.length > 0 && adminView.every((x) => x.userId === 'u_ops'), `${adminView.length} 条 u_ops 记录`);

  const scriptTraces = await dbm.auditQuery(admin, { userId: '*', action: 'run_script', limit: 50 });
  check('脚本执行留痕含 scriptId', scriptTraces.some((x) => x.scriptId === 'fix_region'), `${scriptTraces.length} 条 run_script`);

  // ── MySQL 直连 ──
  console.log('\n== MySQL 直连(账号边界由 DBA 预置)==');
  await waitForMysql(150_000);
  {
    const root = await mysql.createConnection({ host: '127.0.0.1', port: MY_PORT, user: 'root', password: 'mysql_root_pw', database: 'typlm', multipleStatements: true });
    await root.query(`CREATE TABLE IF NOT EXISTS ty_project (id INT AUTO_INCREMENT PRIMARY KEY, project_code VARCHAR(64), region VARCHAR(32)) COMMENT='项目主表'`);
    await root.query(`CREATE TABLE IF NOT EXISTS ty_secret (id INT AUTO_INCREMENT PRIMARY KEY, token VARCHAR(128), project_id INT, FOREIGN KEY (project_id) REFERENCES ty_project(id))`);
    await root.query(`INSERT INTO ty_project (project_code, region) VALUES ('P7-260001', '华东'), ('LE-260002', '华南')`);
    await root.query(`INSERT INTO ty_secret (token, project_id) VALUES ('sk-mysql-secret', 1)`);
    await root.query(`CREATE USER IF NOT EXISTS 'plm_analyst'@'%' IDENTIFIED BY 'analyst_pw'`);
    await root.query(`CREATE USER IF NOT EXISTS 'plm_ops'@'%' IDENTIFIED BY 'ops_pw'`);
    await root.query(`GRANT SELECT ON typlm.ty_project TO 'plm_analyst'@'%'`);
    await root.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON typlm.ty_project TO 'plm_ops'@'%'`);
    await root.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON typlm.ty_secret TO 'plm_ops'@'%'`);
    await root.query(`FLUSH PRIVILEGES`);
    await root.end();
  }
  const myHealth = await dbm.health(analyst, 'mydev');
  check('MySQL 健康', Object.values(myHealth).every((h) => h.ok), Object.values(myHealth)[0]?.error ?? '');

  const myRows = await dbm.query(analyst, 'mydev', 'SELECT id, project_code FROM ty_project');
  check('MySQL 查询授权表', myRows.rows.length === 2 && myRows.columns.join(',') === 'id,project_code');

  try {
    await dbm.query(analyst, 'mydev', 'SELECT * FROM ty_secret');
    check('MySQL 越权读 → 1142 拒绝', false, '意外成功');
  } catch (e: any) {
    check('MySQL 越权读 → 1142 拒绝', (e.message ?? '').includes('1142'), (e.message ?? '').slice(0, 50));
  }

  const myTables = await dbm.listTables(analyst, 'mydev');
  const myTp = myTables.find((t) => t.name === 'ty_project');
  check('MySQL 表清单含注释与估算行数', myTp?.comment === '项目主表' && (myTp?.estimatedRows ?? 0) >= 2,
    `comment=${myTp?.comment}, rows=${myTp?.estimatedRows}`);

  const myCols = await dbm.describeTable(ops, 'mydev', 'ty_secret');
  const myFk = myCols.find((c) => c.name === 'project_id');
  const myPk = myCols.find((c) => c.name === 'id');
  check('MySQL 列元数据:主键 + 外键', myPk?.isPk === true && myFk?.references?.table === 'ty_project',
    `PK=${myPk?.isPk}, FK=${myFk?.references?.table}`);

  const myWrite = await dbm.run(ops, 'mydev', {
    previewSql: `SELECT COUNT(*) AS c FROM ty_project WHERE region = '西南'`,
    executeSql: `INSERT INTO ty_project (project_code, region) VALUES ('MY-260099', '西南')`
  });
  check('MySQL 写流程(事务批量)', myWrite.execute?.statements[0].ok === true && myWrite.verify?.affectedAfter === 1, myWrite.execute?.text);

  // ── mcp-proxy 回环(上游 = 本项目 mcp-db serve)──
  console.log('\n== mcp-proxy 回环 ==');
  const hubHealth = await dbm.health(analyst, 'hub');
  check('proxy 上游健康(SELECT 1 经内层)', Object.values(hubHealth).every((h) => h.ok), Object.values(hubHealth)[0]?.error ?? '');

  const hubRows = await dbm.query(analyst, 'hub', 'SELECT COUNT(*) AS c FROM typlm.ty_project');
  check('proxy 查询(结构化 JSON 解析)', Number(hubRows.rows[0]?.c) >= 3, `count=${hubRows.rows[0]?.c}`);

  try {
    await dbm.query(analyst, 'hub', 'SELECT * FROM typlm.ty_secret');
    check('proxy 越权透传内层 42501', false, '意外成功');
  } catch (e: any) {
    check('proxy 越权透传内层 42501', (e.message ?? '').includes('42501'), (e.message ?? '').slice(0, 50));
  }

  const hubTables = await dbm.listTables(analyst, 'hub');
  check('proxy 表清单(information_schema 探测)', hubTables.some((t) => t.name === 'ty_project'), `${hubTables.length} 张表`);

  // ── 留痕汇总 ──
  console.log('\n== 审计留痕 ==');
  const lines = fs.existsSync(OUTER_AUDIT) ? fs.readFileSync(OUTER_AUDIT, 'utf8').trim().split('\n') : [];
  const entries = lines.map((l) => JSON.parse(l));
  check('全部动作留痕(含被拒绝的)', entries.length >= 25, `${entries.length} 条`);
  const denials = entries.filter((x) => typeof x.code === 'string' && (x.code.startsWith('DENIED') || x.code === 'NEED_CONFIRM' || x.code === 'NEED_OVERRIDE'));
  check('拒绝/拦截记录带 code 与 userId', denials.length >= 6 && denials.every((x) => x.userId), `${denials.length} 条带 code 的拦截记录`);

  await dbm.close();

  const failed = results.filter((r) => !r.pass);
  console.log(`\n== 结果:${results.length - failed.length}/${results.length} 通过 ==`);
  if (failed.length > 0) {
    for (const f of failed) console.log(`  ✗ ${f.name} — ${f.note}`);
    process.exitCode = 1;
  }
}

main()
  .catch((e) => {
    console.error('e2e 失败:', e);
    process.exitCode = 1;
  })
  .finally(() => {
    for (const c of [PG_CONTAINER, MY_CONTAINER]) {
      try {
        execSync(`docker rm -f ${c}`, { stdio: 'ignore' });
      } catch {}
    }
    console.log('(容器已清理)');
  });
