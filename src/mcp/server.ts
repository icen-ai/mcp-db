import * as readline from 'readline';
import { Authenticator } from '../auth.js';
import { loadConfig } from '../config.js';
import { DbmError } from '../errors.js';
import { Dbm } from '../orchestrator.js';
import { callTool, toolsListPayload } from './tools.js';

// ── MCP server(stdio + JSON-RPC)────────────────────────────────────────────
// 与 dbx-mcp 相同的线路协议(initialize / tools/list / tools/call)。
// 认证:令牌来自环境变量 DBM_TOKEN(或 --token),fail closed。
// 注意:stdout 只输出 JSON-RPC,一切日志走 stderr。

const KNOWN_PROTOCOL_VERSIONS = new Set(['2024-11-05', '2025-03-26', '2025-06-18']);

export interface ServeOptions {
  config?: string;
  token?: string;
}

export async function serveMcp(opts: ServeOptions = {}): Promise<void> {
  const { config: dbmConfig } = loadConfig(opts.config);
  const authenticator = new Authenticator(dbmConfig.users);
  const dbm = Dbm.fromConfig(dbmConfig);
  const token = opts.token ?? process.env.DBM_TOKEN;

  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const write = (msg: any) => process.stdout.write(JSON.stringify(msg) + '\n');

  process.stderr.write(`[mcp-db] ready · envs=${Object.keys(dbmConfig.connections).join(',')} · auth=${token ? 'token' : 'none'}\n`);

  rl.on('line', (line) => {
    const text = line.trim();
    if (!text) return;
    let msg: any;
    try {
      msg = JSON.parse(text);
    } catch {
      write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }

    // 通知(无 id)不回应
    if (msg.id === undefined || msg.id === null) return;

    const respond = (result: any) => write({ jsonrpc: '2.0', id: msg.id, result });
    const respondErr = (code: number, message: string) =>
      write({ jsonrpc: '2.0', id: msg.id, error: { code, message } });

    switch (msg.method) {
      case 'initialize':
        respond({
          protocolVersion: KNOWN_PROTOCOL_VERSIONS.has(msg.params?.protocolVersion)
            ? msg.params.protocolVersion
            : '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'mcp-db', version: '0.1.0' }
        });
        break;

      case 'ping':
        respond({});
        break;

      case 'tools/list':
        respond(toolsListPayload());
        break;

      case 'tools/call': {
        const name = msg.params?.name;
        const args = msg.params?.arguments ?? {};
        if (typeof name !== 'string') {
          respondErr(-32602, 'Invalid params: missing tool name');
          break;
        }
        try {
          const user = authenticator.resolve(token);
          void callTool({ dbm, user }, name, args).then(respond).catch((e: any) => {
            respondErr(-32603, `Internal error: ${e?.message ?? e}`);
          });
        } catch (e) {
          if (e instanceof DbmError) {
            // 认证失败:以工具级错误返回可读指引,而不是协议错误,方便 Agent 自纠
            write({
              jsonrpc: '2.0',
              id: msg.id,
              result: {
                isError: true,
                content: [{ type: 'text', text: `[${e.code}] ${e.message}` }],
                structuredContent: { ok: false, code: e.code, error: e.message }
              }
            });
          } else {
            respondErr(-32603, `Internal error: ${e instanceof Error ? e.message : e}`);
          }
        }
        break;
      }

      case 'resources/list':
        respond({ resources: [] });
        break;

      default:
        respondErr(-32601, `Method not found: ${msg.method}`);
    }
  });

  await new Promise<void>((resolve) => rl.on('close', resolve));
  process.stderr.write('[mcp-db] stdin closed, exiting\n');
}
