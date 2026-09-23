// 端到端验证:docker 起真实 PostgreSQL → 同步权限清单 → 逐项断言安全属性。
// 这是「二次分配不被穿透」的实证:越权请求由数据库以 42501 拒绝,
// 而不是靠中间层 if 挡(中间层只负责提前给出友好报错)。
import { execSync } from 'child_process';
import { Client } from 'pg';
import * as path from 'path';
import { loadConfig } from '../src/config.js';
import { adminClient, applyGrants, planGrants } from '../src/grant-sync.js';
import { Dbm } from '../src/orchestrator.js';
import { isDbmError } from '../src/errors.js';

const CONTAINER = 'dbm-e2e';
const PORT = 55432;

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

async function main() {
  console.log('== 准备:启动 PostgreSQL 容器 ==');
  try {
    execSync(`docker rm -f ${CONTAINER}`, { stdio: 'ignore' });
  } catch {}
  sh(`docker run -d --name ${CONTAINER} -e POSTGRES_USER=dbm_admin -e POSTGRES_PASSWORD=admin_pw -e POSTGRES_DB=typlm -p ${PORT}:5432 postgres:16-alpine`);
  await waitForPg('127.0.0.1', PORT, 'dbm_admin', 'admin_pw', 'typlm', 90_000);

  // 种子数据:一张授权表、一张未授权表
  const seed = new Client({ host: '127.0.0.1', port: PORT, user: 'dbm_admin', password: 'admin_pw', database: 'typlm' });
  await seed.connect();
  await seed.query(`CREATE SCHEMA IF NOT EXISTS typlm`);
  await seed.query(`CREATE TABLE typlm.ty_project (id serial PRIMARY KEY, project_code text, region text)`);
  await seed.query(`CREATE TABLE typlm.ty_secret (id serial PRIMARY KEY, token text)`);
  await seed.query(`INSERT INTO typlm.ty_project (project_code, region) VALUES ('P7-260001', '华东'), ('LE-260002', '华南')`);
  await seed.query(`INSERT INTO typlm.ty_secret (token) VALUES ('sk-should-not-leak')`);
  await seed.end();
  console.log('  种子数据就绪(schema typlm:ty_project ×2 行,ty_secret ×1 行)');

  const { config } = loadConfig(path.join(import.meta.dir, '..', 'tests', 'fixtures', 'dbm.test.json'));
  const dbm = Dbm.fromConfig(config);
  const analyst = config.users.find((u) => u.id === 'u_analyst')!;
  const ops = config.users.find((u) => u.id === 'u_ops')!;
  const admin = config.users.find((u) => u.id === 'u_admin')!;

  // ── 第 1 步:同步前,越权请求应被数据库拒绝(证明墙在同步后才存在) ──
  console.log('\n== 同步前:analyst 凭证尚不存在于数据库 ==');
  try {
    await dbm.query(analyst, 'dev', 'SELECT * FROM typlm.ty_project');
    check('同步前 analyst 无法查询(登录用户不存在)', false, '意外成功');
  } catch (e: any) {
    check('同步前 analyst 无法查询(登录用户不存在)', true, (e.message ?? '').slice(0, 60));
  }

  // ── 第 2 步:权限清单物化 ──
  console.log('\n== 同步:清单 → 原生 GRANT/REVOKE ==');
  const adminConn = adminClient(config.connections.dev);
  await adminConn.connect();
  const plan = await planGrants(adminConn, config, 'dev');
  for (const a of plan.actions) console.log(`    [${a.kind}] ${a.detail}`);
  const { applied } = await applyGrants(adminConn, plan);
  await adminConn.end();
  check('同步完成', applied === plan.actions.length, `应用 ${applied} 条授权语句`);

  // 幂等:再同步一次应为零对象级变更(仅幂等的 SCHEMA USAGE 语句)
  const again = adminClient(config.connections.dev);
  await again.connect();
  const plan2 = await planGrants(again, config, 'dev');
  await again.end();
  const objChanges = plan2.actions.filter((a) => a.sql.includes(' ON TABLE ') || a.sql.includes(' ON SEQUENCE '));
  check('二次同步幂等', objChanges.length === 0, objChanges.map((a) => a.detail).join('; ') || '无对象级变更');

  // ── 第 3 步:授权范围内通行 ──
  console.log('\n== 授权范围内 ==');
  const proj = await dbm.query(analyst, 'dev', 'SELECT id, project_code, region FROM typlm.ty_project');
  check('analyst 查询授权表 ty_project', proj.rows.length === 2 && proj.columns.length === 3,
    `${proj.rows.length} 行,列序 [${proj.columns.join(',')}]`);

  const typed = await dbm.query(analyst, 'dev', 'SELECT id FROM typlm.ty_project WHERE id = 1');
  check('类型保真(id 为 number 而非字符串)', typeof typed.rows[0]?.id === 'number',
    `typeof id = ${typeof typed.rows[0]?.id}`);

  // ── 第 4 步:越权被数据库拒绝(核心安全属性) ──
  console.log('\n== 越权路径(墙在数据库)==');
  try {
    await dbm.query(analyst, 'dev', 'SELECT * FROM typlm.ty_secret');
    check('analyst 读未授权表 ty_secret → 42501 拒绝', false, '意外成功:敏感数据泄露');
  } catch (e: any) {
    check('analyst 读未授权表 ty_secret → 42501 拒绝', (e.message ?? '').includes('42501'), (e.message ?? '').slice(0, 80));
  }

  try {
    await dbm.run(analyst, 'dev', { executeSql: 'INSERT INTO typlm.ty_project (project_code) VALUES (\'HACK-1\')' });
    check('analyst 写授权表 → 42501 拒绝(清单只给了 read)', false, '意外成功');
  } catch (e: any) {
    const viaDb = (e.message ?? '').includes('42501');
    check('analyst 写授权表被拒', true, viaDb ? '数据库 42501(穿透到 DB 也被挡)' : `中间层提前拒绝:${(e.message ?? '').slice(0, 60)}`);
  }

  // 注入形态:SELECT 后藏 DROP——DDL 在中间层被拒;即便穿透,DDL 权限也不存在
  try {
    await dbm.query(analyst, 'dev', 'SELECT 1; DROP TABLE typlm.ty_secret');
    check('「SELECT 1; DROP TABLE」混合语句被拒', false, '意外成功');
  } catch (e: any) {
    check('「SELECT 1; DROP TABLE」混合语句被拒', true, (e.message ?? '').slice(0, 60));
  }

  // 直接用 analyst 凭证绕过中间层连库(模拟偷到连接串):同样 42501
  const rawClient = new Client({ host: '127.0.0.1', port: PORT, user: 'plm_analyst', password: 'analyst_pw', database: 'typlm' });
  await rawClient.connect();
  try {
    await rawClient.query('SELECT * FROM typlm.ty_secret');
    check('绕过中间层直连(偷到 analyst 凭证)读 ty_secret → 42501', false, '意外成功:中间层之外无防线');
  } catch (e: any) {
    check('绕过中间层直连(偷到 analyst 凭证)读 ty_secret → 42501', e.code === '42501', `SQLSTATE ${e.code}`);
  }
  await rawClient.end();

  // ── 第 5 步:写流程(ops)──
  console.log('\n== 写流程:预演 → 执行 → 核验 ==');
  const writeRes = await dbm.run(ops, 'dev', {
    previewSql: 'SELECT COUNT(*) AS c FROM typlm.ty_project WHERE region = \'西南\'',
    executeSql: 'INSERT INTO typlm.ty_project (project_code, region) VALUES (\'P7-260099\', \'西南\')'
  });
  check('ops 执行写入', writeRes.execute?.statements.every((s) => s.ok) === true, writeRes.execute?.text);
  check('执行后核验生效', writeRes.verify?.affectedAfter === 1, `核验计数 ${writeRes.verify?.affectedAfter}`);

  // ga 确认闸(dev 连接无确认;ga 连接 requireConfirmForWrite)
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
  check('携带口令 → 执行通过', gaConfirm.needConfirm === undefined && gaConfirm.execute?.statements[0].ok === true,
    gaConfirm.execute?.text);

  // ops 在 dev 无 ddl 权限:manifest 未给
  try {
    await dbm.run(ops, 'dev', { executeSql: 'CREATE TABLE typlm.hack (id int)' });
    check('ops 执行 DDL → 中间层 DENIED_OP', false, '意外成功');
  } catch (e: any) {
    check('ops 执行 DDL → 中间层 DENIED_OP', isDbmError(e) && e.code === 'DENIED_OP', e.code ?? '');
  }

  // ── 第 6 步:留痕 ──
  console.log('\n== 审计留痕 ==');
  const fs = await import('fs');
  const auditPath = path.resolve('data', 'audit.jsonl');
  const lines = fs.existsSync(auditPath) ? fs.readFileSync(auditPath, 'utf8').trim().split('\n') : [];
  const entries = lines.map((l) => JSON.parse(l));
  check('全部动作留痕(含被拒绝的)', entries.length >= 9, `${entries.length} 条`);
  const denials = entries.filter((x) => typeof x.code === 'string' && (x.code.startsWith('DENIED') || x.code === 'NEED_CONFIRM'));
  check('拒绝/拦截记录带 code 与 userId', denials.length >= 3 && denials.every((x) => x.userId), `${denials.length} 条带 code 的拦截记录`);

  await dbm.close();

  // ── 汇总 ──
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
    try {
      execSync(`docker rm -f ${CONTAINER}`, { stdio: 'ignore' });
      console.log('\n(容器已清理)');
    } catch {}
  });
