#!/usr/bin/env node
// mcp-db CLI
//   serve            启动 MCP server(stdio)
//   sync [--env x]   把权限清单物化为数据库 GRANT/REVOKE(幂等 diff)
//   check [--env x]  健康探测 + 权限矩阵
import { serveMcp } from './mcp/server.js';
import type { ConnectionConfig } from './config.js';

function endpointOf(conn: ConnectionConfig): string {
  if (conn.type === 'mcp-proxy') return `${conn.command} ${(conn.args ?? []).join(' ')}`.trim();
  return `${conn.host}:${conn.port}/${conn.database}`;
}
import { loadConfig } from './config.js';
import { adminClient, applyGrants, planGrants } from './grant-sync.js';
import { Dbm } from './orchestrator.js';

interface CliArgs {
  command: string;
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): CliArgs {
  const [command = 'help', ...rest] = argv;
  const flags = new Map<string, string | boolean>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) {
        flags.set(a.slice(2, eq), a.slice(eq + 1));
      } else if (rest[i + 1] && !rest[i + 1].startsWith('--')) {
        flags.set(a.slice(2), rest[++i]);
      } else {
        flags.set(a.slice(2), true);
      }
    }
  }
  return { command, flags };
}

const HELP = `mcp-db(@icen.ai/dbm)- 数据库中间层

用法:
  mcp-db serve  [--config <path>] [--token <t>]   以 MCP server 形式运行(stdio)
  mcp-db sync   [--config <path>] [--env <id>] [--dry-run] [--rotate-passwords]
                                                       同步权限清单 → 数据库 GRANT/REVOKE
  mcp-db check  [--config <path>] [--env <id>]    连接健康 + 权限矩阵

环境变量:
  DBM_CONFIG  配置文件路径(默认 ./dbm.config.json)
  DBM_TOKEN   serve 模式的访问令牌(--token 优先)

配置默认支持 \${ENV_NAME} 插值:密码写占位符,真值走环境变量。`;

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));
  const configPath = typeof flags.get('config') === 'string' ? (flags.get('config') as string) : undefined;

  if (command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return;
  }

  if (command === 'serve') {
    const token = typeof flags.get('token') === 'string' ? (flags.get('token') as string) : undefined;
    await serveMcp({ config: configPath, token });
    return;
  }

  const { config, scripts } = loadConfig(configPath);

  if (command === 'sync') {
    const envFlag = flags.get('env');
    const envs = typeof envFlag === 'string' && envFlag ? [envFlag] : Object.keys(config.connections);
    const dryRun = flags.get('dry-run') === true;
    const rotate = flags.get('rotate-passwords') === true;

    for (const env of envs) {
      const conn = config.connections[env];
      const admin = adminClient(conn);
      await admin.connect();
      try {
        const plan = await planGrants(admin, config, env, { rotatePasswords: rotate });
        console.log(`\n== ${env}(${endpointOf(conn)}, schema ${conn.schema})==`);
        for (const w of plan.warnings) console.log(`  ⚠ ${w}`);
        if (plan.actions.length === 0) {
          console.log('  权限已同步,无需变更。');
        }
        for (const a of plan.actions) {
          console.log(`  [${a.kind}] ${a.detail}`);
          if (dryRun) console.log(`        ${a.sql}`);
        }
        if (!dryRun) {
          const { applied } = await applyGrants(admin, plan);
          console.log(`  ✓ 已应用 ${applied} 条授权语句。`);
        } else {
          console.log('  (dry-run,未执行)');
        }
      } finally {
        await admin.end().catch(() => {});
      }
    }
    return;
  }

  if (command === 'check') {
    const envFlag = flags.get('env');
    const envs = typeof envFlag === 'string' && envFlag ? [envFlag] : Object.keys(config.connections);
    let allOk = true;

    const dbm = Dbm.fromConfig(config, { scripts });
    const adminUser = config.users[0];
    for (const env of envs) {
      const conn = config.connections[env];
      console.log(`\n== ${env}(${endpointOf(conn)})==`);
      const health = await dbm.health(adminUser, env);
      for (const [key, h] of Object.entries(health)) {
        const mark = h.ok ? '✓' : '✗';
        if (!h.ok) allOk = false;
        console.log(`  ${mark} ${key.padEnd(16)} ${h.ok ? `${h.latencyMs}ms` : h.error ?? '失败'}`);
      }
      console.log('  权限矩阵:');
      for (const g of config.grants.filter((x) => x.env === env)) {
        const tables = g.tables === '*' ? '(全部表)' : `${g.tables.length} 张表`;
        console.log(`    角色 ${g.role.padEnd(10)} ${g.ops.join('+').padEnd(14)} ${tables} @ ${g.schema}`);
      }
      for (const u of config.users) {
        const roles = u.roles[env];
        if (roles?.length) console.log(`    用户 ${u.id.padEnd(10)} → ${roles.join(', ')}`);
      }
    }
    process.exitCode = allOk ? 0 : 1;
    return;
  }

  console.error(`未知命令:${command}\n`);
  console.log(HELP);
  process.exitCode = 2;
}

main().catch((e) => {
  console.error(`[mcp-db] ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
