# mcp-db

数据库中间层:**直连 Provider(角色×连接池)+ 权限清单物化为数据库原生 GRANT + 预演/确认/护栏/执行/核验/留痕编排**。npm 包名 `mcp-db`(内部曾用名 @icen.ai/dbm),以 MCP server(stdio)对外暴露给 Agent 挂载——一层两吃,Agent 拿到的是**流程**,不是裸连接。

```
用户/Agent → token 认证 → 角色解析
                ↓
        编排层(UX 护栏:语句分类 + 脚本注册表 + 提前拒绝 + 留痕)
                ↓ 按角色选池(最小权限)
        Pool(analyst 只读)/ Pool(ops 读写)/ Pool(admin)
                ↓
        PostgreSQL / MySQL 原生 GRANT —— 真正的墙
                ↘ mcp-proxy:桥接现成 MCP 数据源(dbhub 等),上游自治认证
```

## 安全模型:为什么「不被穿透」

判断标准一句话:**攻击者无论绕过应用、注入 SQL 还是偷走连接配置,拿到的权限上限 = 他偷到的那条连接本身的 GRANT 范围。**

- 权限的唯一事实源是配置里的 `grants` 清单;`mcp-db sync` 把它**物化**为数据库原生 `GRANT`/`REVOKE`(幂等 diff,含 serial 序列的 `USAGE`)。
- 每个角色一个独立连接池(模式 A);请求路径上不存在换池或提权通道。
- 中间层的语句分类只是 UX 护栏(提前拒绝 + 友好报错 + 审计上下文),fail closed:无法识别的语句按最高危处理。
- admin 凭证仅用于同步,其权限来自 DBA 身份,不在清单管理范畴。

已在真实 PostgreSQL + MySQL 上端到端验证(`bun run e2e`,40 项断言):**偷走 analyst 凭证、绕过中间层直连数据库读未授权表,依然被 42501/1142 拒绝**。这就是「二次分配不被穿透」的实证。

## 三类写防线(全部二段式:首次拦截 → 携凭证放行)

| 防线 | 触发条件 | 放行方式 |
|---|---|---|
| 生产确认 | `requireConfirmForWrite` 连接上的写/DDL | 携带 `confirm` 口令(默认「生产执行」) |
| 爆炸半径护栏 | 预演影响行数 > `maxAffectedRows`(默认 1000) | 携带 `override: true` |
| 权限闸 | 语句类别超出角色 ops | 无放行通道,只能改清单 + sync |

## 快速开始

```bash
bun install
cp dbm.example.json dbm.config.json   # 编辑连接/清单/用户;密码可用 ${ENV} 占位

# 1) 同步权限清单 → 数据库(幂等;先 --dry-run 看计划;仅 postgres 连接)
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

工具面(10 个,全部走认证与留痕):

| 工具 | 说明 |
|---|---|
| `dbm_whoami` | 当前身份、各环境角色与操作权限 |
| `dbm_health` | 逐角色连接探测(延迟/错误) |
| `dbm_list_tables` / `dbm_describe_table` | 表目录(注释/估算行数/大小)/列元数据(物理类型、主键、**外键指向**) |
| `dbm_query` | 只读通道:语句类型闸 + 最小权限池双保险,类型保真,自动限流 |
| `dbm_preview` | 预演:影响行数 + 前 10 行抽样 |
| `dbm_run` | 唯一裸写入口:预演 → 生产确认 → 行数护栏 → 事务执行 → 核验 |
| `dbm_list_scripts` / `dbm_run_script` | **脚本注册表**:预审过的操作,Agent 只传参数不碰 SQL 文本 |
| `dbm_audit` | 审计回查:查自己随时;查他人需 ddl 级角色 |

另有 MCP **resources**:`dbm://{env}/{schema}/tables`(表目录)与 `dbm://{env}/{schema}/{table}`(列元数据),偏好资源形态的客户端可直接读。

### 脚本注册表:从「裸 SQL 通道」到「流程资产」

生产高频操作(修状态、补数据)应沉淀为脚本:配置里声明 `previewSql`/`executeSql` 模板与参数 schema,Agent 调 `dbm_run_script` 只传参数。参数以**字面量**进入 SQL(`:name` 占位符,数字/布尔强校验,字符串单引号转义)——值里的任何注入载荷都只是数据。脚本自带环境白名单;审计记录带 `scriptId`,留痕从「一段 SQL」升级为「一次业务动作」。

## 连接三态

| type | 说明 | 权限墙 |
|---|---|---|
| `postgres` | `pg` 直连,角色×连接池;**支持 sync 物化 GRANT** | 数据库原生 GRANT(最强) |
| `mysql` | `mysql2` 直连,同一契约(注释/主键/FK/事务批量齐备) | DBA 预置账号(CREATE USER + GRANT) |
| `mcp-proxy` | 桥接现成 MCP 数据源(dbhub / 本项目 mcp-db…),子进程 stdio JSON-RPC,JSON/Markdown 双解析 | 上游服务的自有认证 |

`mcp-proxy` 的工具映射:`tools.query = { name: "execute_sql", args: { sql: "$sql", maxRows: "$maxRows" } }`,`$sql`/`$maxRows` 会被实际值替换;声明 `dialect: postgres|mysql` 后 list/describe 走 information_schema 自动探测。

## 配置参考

见 `dbm.example.json`。要点:

- `connections.<env>`:三态联合;`maxAffectedRows` 爆炸半径阈值;`requireConfirmForWrite` + `confirmPhrase` 生产确认。
- `roles`:角色 → 登录凭证,即连接池定义;`admin` 角色供 `sync` 使用(mcp-proxy 用单角色 `default`,无凭证)。
- `grants[]`:权限清单。`ops`: `read` → `GRANT SELECT`;`write` → +`INSERT/UPDATE/DELETE`;`ddl` 不做表级物化。`tables: "*"` 通配。
- `users[]`:token → 用户 → 各环境角色。token 建议走 `${ENV}` 注入。
- `scripts[]`(或 `scriptsFile` 外置):脚本注册表。
- 所有标识符(连接名/角色/用户/schema/表)有白名单校验,从源头堵死配置注入。

## 库用法

```ts
import { loadConfig, Dbm } from 'mcp-db';

const { config, scripts } = loadConfig('dbm.config.json');
const dbm = Dbm.fromConfig(config, { scripts });
const user = config.users[0];

const rows = await dbm.query(user, 'dev', 'SELECT * FROM typlm.ty_project', 100);
const res = await dbm.run(user, 'dev', {
  previewSql: 'SELECT id FROM typlm.ty_project WHERE region = \'华东\'',
  executeSql: 'UPDATE typlm.ty_project SET region = \'华东\' WHERE id = 1'
});
const scripted = await dbm.runScript(user, 'dev', 'fix_project_region', { code: 'P7-260001', region: '华东' });
const trail = await dbm.auditQuery(user, { action: 'run_script', limit: 20 });
```

## 测试

```bash
bun test          # 77 项单测:sql-guard / 权限 / GRANT diff / 配置校验 / 脚本渲染注入 / MCP 握手认证与 resources
bun run e2e       # Docker 双容器(PG + MySQL)40 项:越权 42501/1142、绕过直连、护栏、脚本注入、审计越权、proxy 回环
```

## 已知边界(诚实清单)

- **列级权限**:`GRANT SELECT(col1,col2)` 原生存在但 `SELECT *` 会报错,与通用表格工具不友好——需要 SQL 改写,二期。
- **MySQL 无 sync**:权限清单仍驱动 UX 检查,但数据库侧账号由 DBA 预置(MySQL 的 grant 表含通配符条目,可靠 diff 需读 mysql.db/tables_priv,收益比暂不高)。
- **mcp-proxy 的墙在上游**:桥接连接的越权拒绝依赖上游服务自己的认证;权限清单在该连接上只有 UX 层意义。
- **DDL 不做表级物化**:表结构变更走 admin 凭证直连(即 DBA 范畴)。
- **元数据可见性**:表清单/列名默认对有 USAGE 的角色可见(information_schema 按特权过滤,但 catalog 本身可读);表名本身敏感时需对较新版本 PG 做 catalog REVOKE。
- **预演语义**:影响行数 = 预演 SQL 结果集行数(与 plm-office 一致);聚合型预演要返回明细行而非 COUNT。
- 凭证保管:当前为配置文件 + 环境变量;后续可接 OS keychain。生产建议配合独立网段部署(ga 凭证不落开发者工作站)。

## 设计文档

架构讨论稿见 `plm-office` 仓库 `docs/temp_db_core_dev.md`;本仓库是其落地实现。
