# 防薅羊毛工具包（参考代码）

从一个线上项目中摘出来的防薅核心代码，**仅供参考，不保证能直接编译**。
原项目栈：TanStack Start + Drizzle ORM，跑在 Cloudflare Workers 上（D1 / SQLite，也给了 Postgres、MySQL 的表定义）。

这些工具只实现了能力，**还没有接到任何接口上**。

## 目录

| 路径 | 内容 |
|---|---|
| `service.ts` | 核心：限流/冷却、发放查重与递减、收回、访客积分 |
| `lib/turnstile.ts` | Cloudflare Turnstile 后端校验 |
| `lib/request-identity.ts` | 取 IP、国家、设备指纹 |
| `lib/email-policy.ts` | 邮箱白名单、Gmail 归一化（只做查重 key） |
| `schema/schema.{sqlite,postgres,mysql}.ts` | 三张表的定义，从各方言 schema 文件里截出来的片段 |
| `patches/admin-settings.diff` | 后台配置项、环境变量兜底、公开配置 |
| `patches/api-codes-and-429.diff` | 预留的错误码 -5/-6/-7 和返回 429 的辅助函数 |
| `tests/` | 纯逻辑单测，Node 自带 `node:test`，不连数据库 |

原项目里的 import 路径（`@/config/db/schema`、`@/core/db`、`@/lib/...`）没有改，搬到别的项目需要自己换。

## 三张表

| 表 | 作用 | 一行代表 |
|---|---|---|
| `abuse_rate_limit` | 限流计数器，存数据库所以多个 Worker 实例共享 | 一个 `scope\|subject` 的计数窗口 |
| `grant_record` | 送分的决策流水，查重全靠它 | 一次送分事件（拒绝也记，amount=0） |
| `guest_quota` | 访客余额，按 anon_id 一人一行 | 一个访客账户：`credits` 累计发放，`used` 累计消耗 |

注册用户的余额不在这里，沿用原项目的 `credit` 表。`grant_record.credit_id` 指向那边对应的行。

## 核心逻辑

### 限流 `hitRateLimit`

固定窗口计数。`subject` 是任意字符串，可以是 anon_id、邮箱、指纹、IP 或它们的组合。

- 拼成一个 subject（如 `指纹|IP`）表示“且”：两者都相同才共用一个计数器
- 分开调用多次表示“或”：任何一个维度超限就拒绝，更严格
- `limit: 1` 就是冷却；配 `blockMs` 就是超限后硬封一段时间（防爆破）

### 送分判定 `decideGrant`（纯函数）

按顺序判定，命中即返回：

| 条件 | decision | 发多少 |
|---|---|---|
| 同一 subject 在同一入口领过 | `duplicate` | 0 |
| 指纹和 IP 都拿不到（判定为脚本） | `no_signal` | 0 |
| 国家在禁发列表（默认 IN） | `blocked_region` | 0 |
| 指纹、IP 都没匹配过 | `new` | 全额 |
| 匹配次数 n ≥ `maxRepeats` | `max_repeats` | 0 |
| 指纹和 IP 都匹配 | `same_person` | min(最小额度, 衰减值) |
| 只有指纹匹配 | `fp_match` | max(最小额度, 衰减值) |
| 只有 IP 匹配 | `ip_match` | max(最小额度, 衰减值) |

衰减值 = `max(0, 全额 - n × decayStep)`，`decayStep` 默认 1，后台可配。结果始终在 `[0, 全额]` 之间。

n 不存在任何字段里。每次判定时现场数 `grant_record` 中符合条件的行：未收回、amount>0、scene 在 `priorScenes` 范围内。

**举例**：访客额度 10、最小额度 2、step 3。新设备第一次领 10；清 cookie 后同设备同 IP 再来，判 `same_person`，拿 2；换 IP 再来，判 `fp_match`，n=2，拿 max(2, 10-6) = 4；第三次匹配达到上限，拿 0。

### 收回

- `revokeGrant(流水id)`：作废**一笔**发放。访客直接从 `guest_quota` 扣回；注册用户返回 `creditId`，由调用方去积分模块作废
- `revokeGuestQuota(anonId)`：封**整个访客账户**，之后余额永远读作 0

### 访客扣分 `consumeGuestCredits`

D1 不支持事务。做法是带条件更新（`where used = 读到的旧值`），同时写入一个随机 `last_op_id`，再读回来比对，判断这次更新是否成功。最多重试 3 次。

## 计划中的接线方式

| 入口 | 调用 |
|---|---|
| 注册 | `checkEmailPolicy` + `verifyTurnstileToken` + `hitRateLimit(signup_ip)` + `grantAllowance(scene 'signup', subjectType 'email')` |
| 登录 | `verifyTurnstileToken` + 失败次数 `hitRateLimit(login_fail_*, blockMs)`，成功后 `clearRateLimit` |
| 验证码 | `verifyTurnstileToken` + 按邮箱和按 IP 分别 `hitRateLimit` |
| 任务提交 | 访客：`hitRateLimit(guest_submit)` + `consumeGuestCredits`；注册用户走原积分模块 |
| 签到 | `getDeviceGrantTotals` 合并同设备多账号，做每日上限 |

注册时如果要识别“先当访客领过的人”，`grantAllowance` 需要传 `priorScenes: ['guest', 'signup']`。

## 已知不足

- `grantAllowance` 先查重再发分，中间没有锁。同一 subject 的两个请求同时到达时，可能都被判成新用户
- `hitRateLimit` 新建计数器时会吞掉所有插入错误，不只是主键冲突
- `baseAmount` 没有上限。后台误填一个巨大的数字时，SQLite 会照发，Postgres/MySQL 会因整数溢出而报错
- 只在本地 SQLite 上实测过。Postgres、MySQL、D1 上没有跑过
