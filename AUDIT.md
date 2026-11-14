# pay-gateway 安全自评审报告（AUDIT）

- 评审日期：2026-11-14
- 评审范围：`app/config.py`、`app/main.py`、`app/service.py`、`app/store.py`
- 覆盖链路：上游支付回调（`POST /webhook/payment`）、退款（`POST /refund`）、订单查询（`GET /orders/{order_id}`）
- 约束遵守：路由路径、请求/响应字段名、环境变量名与默认值、数据库路径均未改动；未引入新依赖
- 验证方式：每个问题对应 `tests/test_security.py` 中的攻击用例，修复前全部失败（14 failed），修复后与 `tests/test_functional.py` 一并全绿（20 passed），并发用例连跑 5 轮稳定

## 问题清单

### 1. 回调验签使用非恒定时间比较（时序侧信道）

- **位置**：`app/service.py:26-30`（修复前），`if expected == signature`
- **攻击路径**：攻击者向 `/webhook/payment` 反复发送带猜测签名的请求，通过响应耗时差异逐字节推断正确 HMAC-SHA256 签名；猜对后即可伪造任意支付回调。
- **影响**：验签可被绕过，进而伪造入账，属于支付网关的最高危问题。
- **修复方式**：改用 `hmac.compare_digest`（`app/service.py:32`）做恒定时间比较，并对签名类型做防御性校验。
- **对应测试**：`test_signature_verification_uses_constant_time_compare`（通过 monkeypatch 监听 `hmac.compare_digest` 确认验签确实走恒定时间路径）

### 2. 完整卡号写入应用日志（敏感支付数据泄露，违反 PCI-DSS）

- **位置**：`app/service.py:40-41`（修复前），`logger.info(... card=%s", ..., payload.get("card_no", ""))`
- **攻击路径**：`PAY_LOG_CARD` 默认开启（默认值 `"1"`，受约束不能改），任何能读取日志文件/日志平台的人（运维、第三方日志服务、拿到日志只读权限的攻击者）都能直接拿到完整 PAN。
- **影响**：银行卡号明文泄露，触发 PCI-DSS 不合规与持卡人资金风险。
- **修复方式**：新增 `mask_card()`（`app/service.py:36-42`），日志与入库前统一脱敏为仅保留后四位（如 `************4242`）；开关 `PAY_LOG_CARD` 的名字与默认值保持不变，仅改变其打印内容。
- **对应测试**：`test_webhook_must_not_log_full_card_number`（在 `PAY_LOG_CARD=1` 下断言 caplog 中不出现完整卡号）

### 3. 订单查询接口回显完整卡号

- **位置**：`app/main.py:35-40`（修复前），直接 `dict(row)` 返回，`card_no` 字段为明文
- **攻击路径**：任意能访问 `GET /orders/{order_id}` 的调用方（接口本身无鉴权，见残余风险 R2）枚举订单号即可收割卡号；响应也可能被下游访问日志、前端缓存留存。
- **影响**：与问题 2 同源的 PAN 泄露，但泄露面是 API 消费方而非日志。
- **修复方式**：响应字段名 `card_no` 保持不变，返回前在 `app/main.py:49` 再做一次防御性脱敏（即使库内存有历史明文也不会回显）。
- **对应测试**：`test_order_response_masks_card_number`（断言字段仍存在、不含完整 PAN、以原后四位结尾）

### 4. 回调入账缺少金额与字段校验（负金额 / 浮点截断 / 畸形请求导致 500）

- **位置**：`app/service.py:36,43`（修复前），`int(payload["amount_cents"])` 与 `payload["order_id"]` 直接下标取值；`app/main.py:20`（修复前）`await request.json()` 未捕获异常
- **攻击路径**：
  1. 持有效签名的上游账号（或签名泄露后，配合问题 1）发送 `amount_cents: -100000`，负金额订单被写入账本；
  2. 发送 `amount_cents: 1.5`，`int()` 静默截断为 1 分入账，造成账实不符；`true` 会被 `int(True)` 接受为 1；
  3. 缺 `order_id` 抛 `KeyError`、请求体不是 JSON 抛 `JSONDecodeError`，均以未处理异常返回 500，可被用于探测与拒绝服务。
- **影响**：账目可被污染（负金额还会与退款逻辑联动放大风险），接口健壮性差、错误信息泄露内部堆栈。
- **修复方式**：
  - 新增 `_require_positive_int()`（`app/service.py:45-49`）：排除 `bool`、非 `int`、≤0 的值；
  - `handle_webhook()` 校验 `order_id` 为非空字符串、`card_no` 为字符串，非法输入抛 `WebhookError` → 400（`app/service.py:52-66`）；
  - `app/main.py:21-23` 捕获 JSON 解析异常统一返回 400。
- **对应测试**：`test_webhook_rejects_negative_amount`、`test_webhook_rejects_zero_amount`、`test_webhook_rejects_non_integer_amount`（含浮点与布尔）、`test_webhook_rejects_missing_order_id`、`test_webhook_rejects_malformed_json`

### 5. 退款接受负数 / 零 / 浮点金额，且缺字段时 500

- **位置**：`app/main.py:30`（修复前）`int(body["amount_cents"])`；`app/service.py:48-55`（修复前）无正负与类型校验
- **攻击路径**：
  1. 对订单发起 `amount_cents: -500` 的退款，`refunded_cents` 被反向减少，可退额度不降反增，随后可反复套取超额退款，直接造成资金损失；
  2. `amount_cents: 1.99` 被截断为 1，产生非预期退款；
  3. 缺 `order_id` / `amount_cents` 时 `KeyError` 以 500 暴露。
- **影响**：资金损失 + 接口可被异常请求打挂。
- **修复方式**：`service.refund()` 入口严格校验（`app/service.py:78-84`，拒绝 bool、非 int、≤0、空 order_id）；`app/main.py:34-36` 先检查必填字段再调用，统一 400。
- **对应测试**：`test_refund_rejects_negative_amount`（同时断言库内 `refunded_cents` 保持 0）、`test_refund_rejects_zero_amount`、`test_refund_rejects_fractional_amount`、`test_refund_rejects_missing_fields`

### 6. 退款 check-then-act 竞态（TOCTOU），并发可超额退款

- **位置**：`app/service.py:48-54`（修复前）先 `get_order` 判断额度、再调 `store.add_refund`；`app/store.py:53-62`（修复前）为无条件 `UPDATE ... + ?`，两次调用各开一个连接
- **攻击路径**：对同一订单并发发起 N 笔退款请求，所有请求在任一写库前都读到相同的 `refunded_cents`，全部通过额度判断，累计退款超过订单金额。测试中用 8 线程 × 600 分对 1000 分订单稳定复现超额。
- **影响**：直接资金损失，且可被脚本化批量利用。
- **修复方式**：把“额度检查 + 落账”合并为单条带条件的原子 UPDATE（`app/store.py:57-72`，`WHERE ... refunded_cents + ? <= amount_cents`），由 SQLite 写锁串行化；`service.refund()` 保留预检用于友好报错，并以原子 UPDATE 的 `rowcount` 兜底（`app/service.py:92-93`）。同时连接增加 `busy_timeout=5000`（`app/store.py:12-13`）避免并发写直接报 locked。
- **对应测试**：`test_concurrent_refunds_cannot_exceed_order_amount`（门控线程放大竞态窗口，断言累计退款 ≤ 订单金额、成功笔数受限）

### 7. 回调幂等只存在进程内存，重启 / 多副本下失效

- **位置**：`app/service.py:11,37,44`（修复前），模块级 `_processed: set`
- **攻击路径**：上游支付通道对同一回调天然会重试（超时、网络抖动）。服务重启或多副本部署后内存集合清空，重复回调再次执行入账；原 `INSERT OR IGNORE` 的结果又被忽略，调用方无从感知是否重复。
- **影响**：重复记账、对账失败；在与退款联动时可放大资金差错。
- **修复方式**：删除内存集合，以数据库主键冲突作为幂等判据：`store.create_order()` 返回 `rowcount == 1` 区分新插入与已存在（`app/store.py:43-54`），`handle_webhook()` 据此返回 `ok` / `duplicate`（`app/service.py:72-76`）。响应字段与取值（`status`）保持不变。
- **对应测试**：`test_duplicate_webhook_is_idempotent_without_in_memory_state`（清空进程状态后重放同一签名回调，断言返回 duplicate 且库内仅一行）

## 已核查但确认无问题的点

- **SQL 注入**：`store.py` 全部语句均为参数化占位符（`?`），未发现字符串拼接 SQL。
- **签名覆盖**：验签针对的是原始请求字节 `raw_body`，而非解析后的 dict，不存在通过 JSON 重排/重复键绕开签名内容的空间；`x-signature` 缺失时按空串处理，比较必然失败。

## 受约束无法彻底修复的残余风险

### R1. 内置默认回调密钥 `pay-dev-secret` 仍在代码兜底值中

- **原因**：要求（5）明确禁止改动环境变量默认值，无法删除或替换该默认密钥。
- **残余风险**：若生产部署遗漏设置 `PAY_WEBHOOK_SECRET`，攻击者用公开的默认密钥即可伪造通过验签的回调（问题 1、4 的修复只防猜签名和非法参数，防不住“合法签名的恶意内容”）。
- **已做缓解**：`app/config.py:11-15` 在检测到使用默认值时启动即打印 WARNING，提示部署侧覆盖。
- **后续建议**：上线 checklist 强制校验该环境变量；中期把默认值改为缺失时拒绝启动（需放宽约束后实施），并将密钥迁入 KMS/密管系统并支持轮换。

### R2. `/refund` 与 `/orders/{order_id}` 无身份认证与授权

- **原因**：当前公开接口只有这四个路由且没有任何鉴权层；新增鉴权头/令牌机制属于接口与运行配置变更，超出本次允许范围。
- **残余风险**：任何网络可达者都能发起退款（问题 5、6 只保证“退不错账”，不保证“谁能退”）或枚举订单号读取订单信息（问题 3 已保证读不到完整 PAN，但金额、订单存在性仍泄露）。
- **后续建议**：网关侧加 mTLS 或内网访问控制 + 服务间签名令牌；`/orders` 增加调用方授权与订单归属校验。

### R3. 无限流 / 无请求体大小限制，存在 DoS 面

- **原因**：限流与 body 限额属于部署/框架配置，受“不许改运行配置、不引入新依赖”约束，本次未加。
- **残余风险**：畸形 JSON 虽已不再产生 500，但攻击者仍可高频打接口消耗 SQLite 写锁与连接资源；超大请求体在 `await request.body()` 阶段占用内存。
- **后续建议**：在上游反向代理（Nginx/网关）配置 `client_max_body_size` 与速率限制；并发模型当前为每请求新建 SQLite 连接，量大时建议引入连接池（需评估依赖）。

### R4. `PAY_LOG_CARD` 默认仍为开启

- **原因**：环境变量默认值禁止改动。
- **残余风险**：已大幅降级——日志中现在只有脱敏后四位，不构成完整 PAN 泄露；但后四位 + 订单号仍属轻度敏感信息，默认打印会扩大不必要的信息面。
- **后续建议**：部署时显式设置 `PAY_LOG_CARD=0`；待约束放宽后将默认值翻转为关闭。

### R5. 历史库数据中的明文卡号

- **原因**：本次只改代码逻辑与数据库路径无关的表结构未动，不能在评审窗口内贸然做数据迁移。
- **残余风险**：修复前入库的 `card_no` 仍是明文；查询接口已做防御性脱敏（问题 3），API 不会回显，但拿到库文件只读权限者仍可直接读取。
- **后续建议**：排一次数据修复任务，将存量 `card_no` 批量改写为脱敏值（或清空），并收紧 SQLite 文件的系统权限。
