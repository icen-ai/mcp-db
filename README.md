# @icen.ai/dbm · mcp-db

数据库中间层:**直连 Provider(角色×连接池)+ 权限清单物化为数据库原生 GRANT + 预演/确认/执行/核验/留痕编排**。对内是 npm 库(`@icen.ai/dbm`),对外以 MCP server(`mcp-db`,stdio)暴露给 Agent 挂载——一层两吃,Agent 拿到的是**流程**,不是裸连接。

```
用户/Agent → token 认证 → 角色解析
                ↓
        编排层(UX 护栏:语句分类 + 提前拒绝 + 留痕)
                ↓ 按角色选池(最小权限)
        Pool(analyst 只读)/ Pool(ops 读写)/ Pool(admin)
                ↓
        PostgreSQL 原生 GRANT —— 真正的墙
```

## 安全模型:为什么「不被穿透」

判断标准一句话:**攻击者无论绕过应用、注入 SQL 还是偷走连接配置,拿到的权限上限 = 他偷到的那条连接本身的 GRANT 范围。**

- 权限的唯一事实源是配置里的 `grants` 清单;`mcp-db sync` 把它**物化**为数据库原生 `GRANT`/`REVOKE`(幂等 diff,含 serial 序列的 `USAGE`)。
- 每个角色一个独立连接池(模式 A);请求路径上不存在换池或提权通道。
- 中间层的语句分类只是 UX 护栏(提前拒绝 + 友好报错 + 审计上下文),fail closed:无法识别的语句按最高危处理。
- admin 凭证仅用于同步,其权限来自 DBA 身份,不在清单管理范畴。

已在真实 PostgreSQL 上端到端验证(`bun run e2e`,16 项断言):**偷走 analyst 凭证、绕过中间层直连数据库读未授权表,依然被 42501 拒绝**。这就是「二次分配不被穿透」的实证。

## 快速开始

```bash
bun install
cp dbm.example.json dbm.config.json   # 编辑连接/清单/用户;密码可用 ${ENV} 占位

# 1) 同步权限清单 → 数据库(幂等;先 --dry-run 看计划)
bun src/cli.ts sync --dry-run
bun src/cli.ts sync

# 2) 健康与权限矩阵检查
bun src/cli.ts check

# 3) 以 MCP server 运行(stdio)
DBM_TOKEN=<用户 token> bun src/cli.ts serve
```

生产部署:`bun run build` 后用 `node dist/cli.js serve`(bin 名 `mcp-db`)。

## 作为 MCP server 接入 Agent

```json
{
  "mcpServers": {
    "mcp-db": {
      "command": "node",
      "args": ["C:/Users/dp09/.code/icen/mcp-db/dist/cli.js", "serve", "--config", "C:/path/dbm.config.json"],
      "env": { "DBM_TOKEN": "用户的访问令牌" }
    }
  }
}
```

工具面(全部走认证与留痕):

| 工具 | 说明 |
|---|---|
| `dbm_whoami` | 当前身份、各环境角色与操作权限 |
| `dbm_health` | 逐角色连接探测(延迟/错误) |
| `dbm_list_tables` / `dbm_describe_table` | 表清单/列元数据(物理类型、主键、注释) |
| `dbm_query` | 只读通道:语句类型闸 + 最小权限池双保险,类型保真,自动限流 |
| `dbm_preview` | 预演:影响行数 + 前 10 行抽样 |
| `dbm_run` | 唯一写入口:预演 → needConfirm(生产)→ 执行(事务)→ 核验 → 留痕 |

生产环境(`requireConfirmForWrite: true`)首次调用返回 `needConfirm` 与预演结果;用户确认后携带口令(默认「生产执行」)再次调用才真正执行。**提示词注入的 Agent 最坏后果被 GRANT 圈死**——注入变成授权问题,授权由数据库解决。

## 配置参考

见 `dbm.example.json`。要点:

- `connections.<env>.roles`:角色 → 登录凭证,即连接池定义;`admin` 角色供 `sync` 使用。
- `grants[]`:权限清单。`ops`: `read` → `GRANT SELECT`;`write` → +`INSERT/UPDATE/DELETE`;`ddl` 不做表级物化(admin 直连范畴)。`tables: "*"` 通配。
- `users[]`:token → 用户 → 各环境角色。token 建议走 `${ENV}` 注入。
- 所有标识符(连接名/角色/用户/schema/表)有白名单校验,从源头堵死配置注入。

## 库用法

```ts
import { loadConfig, Dbm } from '@icen.ai/dbm';

const { config } = loadConfig('dbm.config.json');
const dbm = Dbm.fromConfig(config);
const user = config.users[0];

const rows = await dbm.query(user, 'dev', 'SELECT * FROM typlm.ty_project', 100);
const res = await dbm.run(user, 'dev', {
  previewSql: 'SELECT COUNT(*) FROM typlm.ty_project WHERE region = \'华东\'',
  executeSql: 'UPDATE typlm.ty_project SET region = \'华东\' WHERE id = 1'
});
```

## 测试

```bash
bun test          # 58 项单测:sql-guard / 权限 / GRANT diff / 配置校验 / MCP 握手与认证
bun run e2e       # Docker 起真实 PG:同步 → 越权 42501 → 写流程 → 确认闸 → 留痕(16 项)
```

## 已知边界(诚实清单)

- **列级权限**:`GRANT SELECT(col1,col2)` 原生存在但 `SELECT *` 会报错,与通用表格工具不友好——需要 SQL 改写,二期。
- **DDL 不做表级物化**:表结构变更走 admin 凭证直连(即 DBA 范畴)。
- **元数据可见性**:表清单/列名默认对所有角色可见(pg_catalog);表名本身敏感时需对较新版本 PG 做 catalog REVOKE。
- **DuckDB(work 本地库)**:无多用户体系,应用层即唯一边界——敏感数据不放本地库。
- **模式 B(SET LOCAL ROLE + RLS 行级)**:接口已预留(编排器按角色选池的落点即可切换),待参数化查询全面落地后启用,可叠加每请求身份与行级策略。
- 凭证保管:当前为配置文件 + 环境变量;后续可接 OS keychain。生产建议配合独立网段部署(ga 凭证不落开发者工作站)。

## 设计文档

架构讨论稿见 `plm-office` 仓库 `docs/temp_db_core_dev.md`;本仓库是其落地实现。
