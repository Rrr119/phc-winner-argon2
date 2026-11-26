# Adaptive Argon2

登录接口在高并发下会把 CPU 打满，而直接调低 Argon2 参数又会削弱离线破解
抗性。本扩展在**不破坏现有 Argon2 PHC 哈希与校验生态**的前提下增加：

1. 基于在飞登录并发数（可附加系统 load average）的自适应参数分级；
2. 与哈希一起存储参数、策略版本和格式版本的版本化信封格式 `$a2ad$`；
3. 对旧版裸 PHC 哈希（`$argon2id$...` / `$argon2i$...`，含 v1.0）的完全
   兼容，stock `argon2*_verify()` 可直接校验信封哈希；
4. 安全地板（security floor），任何档位/外部传入参数都不会低于地板；
5. 内存审计环 + JSON-lines 参数变更审计日志。

公开 API 见 `include/argon2_adaptive.h`，实现见 `src/adaptive.c`，
264 项验收见 `src/adaptive_acceptance.c`。

## 并发分级与安全地板

控制器维护一个受互斥锁保护的在飞请求计数（gauge）。默认策略：

| 并发 active | 档位 tier | t | m (KiB) | p | 说明 |
| ---: | --- | ---: | ---: | ---: | --- |
| 0–7 | `low` | 3 | 65536 | 1 | 低负载，最强 |
| 8–31 | `medium` | 2 | 32768 | 1 | 降压 |
| 32–63 | `high` | 2 | 19456 | 1 | 高负载，仍不低于地板 |
| ≥64 | `high` + overload | 2 | 19456 | 1 | 触发过载建议（排队/限流），参数不再下调 |

验收套件使用 `argon2_adaptive_test_config()` 的确定性快速档位
（阈值 `4 / 16 / 64`，参数 `3/256/2`、`2/128/1`、`1/64/1`，地板
`1/64/1`），以便在 1/8/32 个真实 pthread 并发下秒级完成；分级、地板、
审计逻辑与生产配置完全一致。

档位只随并发“降本”，且始终满足 `floor`；`argon2_adaptive_clamp_params()`
还会补齐 Argon2 的硬约束（`t>=1`、`p>=1`、`m>=8*p` 等）。达到
`critical_threshold` 后只发出 `overload` 事件并建议负载 shedding/队列化，
不会继续削弱哈希。

## 版本化信封格式

```
$a2ad$v=<fmt>$pv=<policy>$tier=<0|1|2>$m=<m>,t=<t>,p=<p>$<reserved>$<stock PHC>
```

实例：

```
$a2ad$v=1$pv=1$tier=0$m=256,t=3,p=2$$argon2id$v=19$m=256,t=3,p=2$<salt>$<digest>
```

- `v`：信封格式版本（`ARGON2_ADAPTIVE_FMT_VERSION = 1`）；
- `pv`：参数策略版本（`ARGON2_ADAPTIVE_POLICY_VERSION = 1`）；
- `tier`：选中该参数时的压力档位；
- `m,t,p`：**实际使用**的参数，便于审计/巡检，真正参与计算的参数以内嵌
  PHC 为准，校验时会交叉比对两者；
- `reserved`：预留字段，当前为空（表现为 `$$`）；
- 末尾是完整的 stock PHC 字符串。

`src/encoding.c` 的 `decode_string()` 在入口识别 `$a2ad$` 并解包到内嵌
PHC，因此**未修改签名的** `argon2id_verify()` / `argon2i_verify()` /
`argon2_verify()`（以及各 `_ctx` 版本）都能直接校验信封；类型前缀仍按
调用方的 verifier 类型严格检查。旧的裸 PHC 哈希走原路径，行为不变。

## 透明升级旧哈希

`argon2_adaptive_needs_rehash(c, encoded)` 返回：

- `1`：裸 PHC 旧哈希、格式/策略版本过旧、或参数低于安全地板；
- `0`：当前策略下的信封哈希；
- `-1`：无法解析。

典型登录流程：

```c
char hash[ARGON2_ADAPTIVE_ENCODED_MAX];

/* 注册/改密：按当前负载选参并生成信封 */
argon2_adaptive_login_hash(pwd, pwdlen, hash, sizeof hash);

/* 登录校验：信封或旧哈希都能验证 */
if (argon2_adaptive_login_verify(stored, pwd, pwdlen) == ARGON2_OK) {
    if (argon2_adaptive_needs_rehash(
            argon2_adaptive_default_controller(), stored) == 1) {
        /* 用当前档位重新哈希并写回数据库 */
    }
}
```

也可以显式使用控制器与 gauge：

```c
argon2_adaptive_config cfg;
argon2_adaptive_controller *c;
argon2_adaptive_default_config(&cfg);
cfg.audit_path = "argon2_param_audit.log";
argon2_adaptive_init(&c, &cfg);

argon2_adaptive_login_start(c);          /* active++ 并可能切换档位/写审计 */
/* ... argon2_adaptive_verify(c, stored, pwd, n) ... */
argon2_adaptive_login_end(c);            /* active--，压力回落时恢复强参数 */

argon2_adaptive_destroy(c);
```

## 审计日志

控制器始终维护一个固定容量的内存审计环
（`argon2_adaptive_audit_count/get`），配置 `audit_path` 后同时追加
JSON-lines 文件。事件类型：`init`、`param_change`、`overload`、
`recovered`。`param_change` 带有完整 old/new 参数增量：

```json
{"ts":"2026-11-25T22:52:47Z","event":"param_change","policy_ver":1,"fmt_ver":1,"old_tier":"low","new_tier":"medium","old":{"t":3,"m":256,"p":2},"new":{"t":2,"m":128,"p":1},"active":8,"load1":null,"overload":0,"trigger":"manual_sample","reason":"pressure up: reducing argon2 cost within security floor"}
{"ts":"2026-11-25T22:52:47Z","event":"overload","policy_ver":1,"active":64,"load1":null,"overload":1,"trigger":"manual_sample","reason":"critical concurrency: keeping security floor and requesting load shedding/queueing"}
```

`trigger` 取值包括 `init` / `manual_sample` / `login_start` /
`login_end` / `evaluate`；`load1` 在系统负载不可采样时为 `null`，否则为
两位小数的 1 分钟 load average。

## 构建与验收

```sh
make test-adaptive   # 构建并运行 264 项自适应验收（追加写 argon2_param_audit.log）
./acceptance.sh      # 清空审计日志后跑验收，并刷新 artifacts/ 中的日志副本
make test            # 上游 KAT + 单元测试 + 264 项自适应验收
make testci          # -Werror + 覆盖率 + TEST_LARGE_RAM 的严格 CI
```

验收覆盖：1/8/32 三种确定性压力档位、64 临界过载与恢复、地板 clamp、
1/8/32 个真实 pthread 并发轮（barrier 保证同时在飞）、信封解析/防篡改、
三种旧哈希（argon2id v19、argon2i v19、argon2i v1.0 m=65536）的 stock
校验与 rehash 标记、默认单例 login API、审计环与 JSON-lines 文件。

代码保持 C89 兼容，可被 C++ 包含链接；定义 `ARGON2_NO_THREADS` 可在无
pthread 模式构建（真实并发阶段自动跳过）。ASan/UBSan/TSan 下验收均零告警。
