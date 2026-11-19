# Test Vectors for the WIMSE S2S Protocol HTTP Signature Scheme — v4

- Author: Jiahui Miao (VERTCITY LLC)
- Date: 2026-11-13
- License: CC-BY-4.0
- Subject specification: draft-ietf-wimse-http-signature-08
- Contents: 29 test vectors (6 positive, 23 negative) plus 3 observation items. All key material is test-only and fully published in Section 2 so that every vector can be recomputed independently.
- Previous version: v3 (28 vectors) is archived on Zenodo as a dataset, DOI 10.5281/zenodo.24184599. Changes since v3: one added boundary vector (N-09b) and the machine-readable anchor layer described below; the P-04 "@authority" correction was already part of v3 and is unchanged.
- Anchor layer: this v4 set adds machine-readable anchors for automated extraction by the companion conformance suite (per-entry anchor lines, the regeneration rule in Section 1, the materials block in Section 2, the set-level rule in Section 5, and the disposition register in Appendix C). No vector message, signature base, signature value, key, timestamp, or expected outcome differs from the finalized v4 set.
- Machine-readable version header:
```text
set_version: v4
draft_version: draft-ietf-wimse-http-signature-08
t0: 1795000000
default_verify_offset_seconds: 60
counts: { positive: 6, negative: 23, observation: 3, judged_total: 29 }
previous_version_archive: doi:10.5281/zenodo.24184599
```

## 0. 修订总账与自验证据

| 向量 | 改动 | 因 |
|---|---|---|
| P-01 | 签名基 `"@query"` 行 `flavor=vanilla` → `?flavor=vanilla`；Signature 值重签 | S1（X1 复现） |
| P-02 | 签名基 `"@query";req` 行同改；Signature 值重签 | S1（X1 复现） |
| P-06 | sig2 签名基 `"@query"` 行同改；sig2 Signature 值重签；sig1（诱饵）不动 | X1（S1 同因） |
| N-15 | 签名基 `@query` 行同改；字面 ES256 签名值按 RFC 6979 重算 | T1（S1 传播） |
| P-04 | 签名基 `"@authority"` 行 `svcb.example.com:443` → `svcb.example.com`；Signature 值以 svcA 密钥同参数重签 | K1（kanywst 提出、Sheffer 同意；自核 RFC 9421 §2.2.3 原文：「the default port is omitted」——443 为 https 默认端口、wimse-aud 亦为 https，规范化值不带端口，原向量不合 RFC 9421，改） |
| N-06/N-07 | 期望与判定式不动；加作者确认注记 | S4（确认型，零字面修订） |
| O-2 | 条目保留；状态注记更新为编辑侧已立项 | S2/S5 |
| N-09b | 新增边界例（验证时刻 T0＋301，其余与 P-01 逐字同） | K2（kanywst #419 建议、我方回帖承诺） |

自验记录（本地独立实现复算，2026-11-06；管线与原验证包同一路径：Ed25519 按 RFC 8032、ES256 按 RFC 6979 确定性 k、同种子派生密钥）：
- 管线等价性先证：由种子派生之全部公钥与已发布 JWK 逐字一致；本件 RFC 6979 实现对已发布 P-03、N-15 签名（旧基）**逐字节复现**，证明与原生成管线同路。
- 缺陷坐实：已发布 P-01/P-02/P-06-sig2/N-15 签名在旧基下验过、在修正基下验不过。
- 修订后自验：新 P-01/P-02/P-06-sig2/N-15 签名在修正基下全部验过；新 P-01 在旧基下验不过（防混用）；新 N-15 在 cnf 声明的 Ed25519 密钥下验不过（负例语义保持）。
- 未改面抽验：P-03/P-05 与 P-06-sig1 的已发布签名对原基复算仍成立；三份 WIT 的 Issuer 签名复算成立。
- v3 P-04 自验（2026-11-12，本地独立实现复算）：管线等价性先证——由 svcA 种子派生的公钥与已发布 JWK 逐字一致，且已发布 P-04 签名在旧基（`svcb.example.com:443`）下验过，证明与原生成管线同路；新签名在修正基（`svcb.example.com`）下验过。连带核：N-02 为文字构造负例（无字面签名值），基准指向自动对位，无传播修订；N-15 基准为 P-01，不受影响。

## 1. 方法与格式约定（与已发布版同）

- **固定验证时钟**：全部向量以 T0＝1795000000（Unix 秒）为 created 基准，验证时刻默认 T0＋60；偏离者逐条显名。expires 一律 created＋300（5 分钟，合草案「on the order of minutes」口径 §3）。
- **密钥全公开**：测试专用密钥（含私钥）全量入 §2，任何人可独立复算；密钥由固定种子确定性派生（派生式入 §2），非生产密钥、不得他用。
- **签名基显式给出**：每条正例附完整 signature base（RFC 9421 §2.5 构造），验证不依赖我方代码即可复现。
- **判定式**：每条向量给「验证方动作序列＋期望终局」；负例的期望终局统一锚到草案 §3.6 错误面（400＋wimse-signature-invalid，或逐条注明的 501/400 与客户端拒绝）。
- **生成与自验**：向量由本地独立实现（Ed25519 按 RFC 8032、ES256 按 RFC 6979 确定性 k）计算，生成时逐条自验签名成立。ES256 签名为 RFC 6979 确定性签名，同输入复算结果恒同。
- **字面签名完备性与再生规则（A-04，定版增补）**：正例与 N-15 的 Signature 值全字面给出；负例中凡注「签名随之重算」或属文字/迁移构造而未给字面值者（N-02、N-06、N-07、N-08、N-10、N-11、N-12、N-13、N-21），其签名由运行器按 §2 材料再生：对基准条目消息施加该条变异后，按草案 §3.1 以 WIT cnf.jwk 绑定密钥重签——Ed25519 签名为确定性签名、ES256 按 RFC 6979 §3.2 确定性 k，故再生结果逐字节可复现。此为明示规则，不许默认推定；逐条机读锚行以 sig=regen 标明适用条目，清单另见附录 C.4。

## 2. 密钥与 WIT 材料（测试专用，全公开，与已发布版全同）

派生式：Ed25519 种子＝SHA-256("s01-validation-vectors:<name>")，JWK 的 d 即种子 base64url；svcC 的 P-256 私钥标量＝SHA-256("s01-validation-vectors:svcC") mod (n−1)＋1。

**Issuer（WIT 签发方）** Ed25519，kid=issuer-key
- 公钥 JWK：{"alg":"Ed25519","crv":"Ed25519","kid":"issuer-key","kty":"OKP","x":"QH_Zu0pnwyO8xdFQm9upOUFAbpb4nhMrGc29L3uJXDA"}
- 私钥 d：4nRAPQQyr8cUgAtCESLc4ZIGIxZT9-guqxcc3wV-2NI

**svcA** Ed25519，kid=vec-a-key（sub＝wimse://example.com/svcA）
- 公钥 JWK：{"alg":"Ed25519","crv":"Ed25519","kid":"vec-a-key","kty":"OKP","x":"O3OfVmPJ3peYhdDrMweNIiBOQU6JZCNcYMK2kjV0i3Y"}
- 私钥 d：F8BhX5poMswcVwTgEMGETOhdN72PaxIiwuGYWrzSUvk

**svcB** Ed25519，kid=vec-b-key（sub＝wimse://example.com/svcB）
- 公钥 JWK：{"alg":"Ed25519","crv":"Ed25519","kid":"vec-b-key","kty":"OKP","x":"4jVAzgEPO5n-6jujSiyQME5t-tIzZApbhR5cTPoedII"}
- 私钥 d：4MaIKp1h5mkTS7ZSawz6QYN6FYA_rOYBPDfGEZCpPDg

**svcC** ES256/P-256，kid=vec-c-key（sub＝wimse://example.com/svcC）
- 公钥 JWK：{"alg":"ES256","crv":"P-256","kid":"vec-c-key","kty":"EC","x":"jZjfUBQgD1l9R_lm4nzo1rP82pGVDBxHD6YmOo_xoCo","y":"CBGv9b8hB-l0mov9rlu223g-vNE_SquCC2IhPi2IweE"}
- 私钥 d：X94ti7AkOiC4JcxdbSmLkwWEzyEU4wMqBX_9LHfXQaU

**other（P-06 诱饵签名方）** Ed25519，kid=other-key
- 公钥 JWK：{"alg":"Ed25519","crv":"Ed25519","kid":"other-key","kty":"OKP","x":"Lo6grJBjN252d2huS1-ckJIql2FZR2vrTOF2qKRBTm4"}
- 私钥 d：KL4_B1CdV7qwZkVYvyK0I5SrsEzv6yb1p1PNAfbC7LY

**WIT-A**（iat＝T0−60，exp＝T0＋3600，jti＝wit-a-1795000000；WIT 生命周期长于签名生命周期，合草案 §3 注记）：
eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiaXNzdWVyLWtleSIsInR5cCI6IndpdCtqd3QifQ.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia2lkIjoidmVjLWEta2V5Iiwia3R5IjoiT0tQIiwieCI6Ik8zT2ZWbVBKM3BlWWhkRHJNd2VOSWlCT1FVNkpaQ05jWU1LMmtqVjBpM1kifX0sImV4cCI6MTc5NTAwMzYwMCwiaWF0IjoxNzk0OTk5OTQwLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsImp0aSI6IndpdC1hLTE3OTUwMDAwMDAiLCJzdWIiOiJ3aW1zZTovL2V4YW1wbGUuY29tL3N2Y0EifQ.JCh9sN__1Al9xVB-K7CFafw1tDV8PCeZvyKdFyMmb9vvN4mK2ZGNbC6VLFpNzpVsgGBV0FwmzerDAFuikSJBCw

**WIT-B**（iat＝T0−60，exp＝T0＋3600，jti＝wit-b-1795000000）：
eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiaXNzdWVyLWtleSIsInR5cCI6IndpdCtqd3QifQ.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVkMjU1MTkiLCJjcnYiOiJFZDI1NTE5Iiwia2lkIjoidmVjLWIta2V5Iiwia3R5IjoiT0tQIiwieCI6IjRqVkF6Z0VQTzVuLTZqdWpTaXlRTUU1dC10SXpaQXBiaFI1Y1RQb2VkSUkifX0sImV4cCI6MTc5NTAwMzYwMCwiaWF0IjoxNzk0OTk5OTQwLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsImp0aSI6IndpdC1iLTE3OTUwMDAwMDAiLCJzdWIiOiJ3aW1zZTovL2V4YW1wbGUuY29tL3N2Y0IifQ.iBAAT-2xF6Polfa49cDu4THgh3zhCdbAitBM5JIgxuuCEdbjMKglKVskt7E78jdE42i3FMMP9-Lw0PLRXwXaBQ

**WIT-C**（iat＝T0−60，exp＝T0＋3600，jti＝wit-c-1795000000）：
eyJhbGciOiJFZDI1NTE5Iiwia2lkIjoiaXNzdWVyLWtleSIsInR5cCI6IndpdCtqd3QifQ.eyJjbmYiOnsiandrIjp7ImFsZyI6IkVTMjU2IiwiY3J2IjoiUC0yNTYiLCJraWQiOiJ2ZWMtYy1rZXkiLCJrdHkiOiJFQyIsIngiOiJqWmpmVUJRZ0QxbDlSX2xtNG56bzFyUDgycEdWREJ4SEQ2WW1Pb194b0NvIiwieSI6IkNCR3Y5YjhoQi1sMG1vdjlybHUyMjNnLXZORV9TcXVDQzJJaFBpMkl3ZUUifX0sImV4cCI6MTc5NTAwMzYwMCwiaWF0IjoxNzk0OTk5OTQwLCJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tL2lzc3VlciIsImp0aSI6IndpdC1jLTE3OTUwMDAwMDAiLCJzdWIiOiJ3aW1zZTovL2V4YW1wbGUuY29tL3N2Y0MifQ.8-bmHNavOVSxyr2hAtnKfrC-kdm5L4XMP4n1cGGMLh5DjSPmdjTWkpKtTO9tPZfKMIfLVC7xGaDvoJXUdizGCg

受信任配置（全部向量共用，除逐条另注）：svcB 验证方信任的 wimse-aud 集合＝{"https://svcb.example.com/gimme-ice-cream", "https://svcb.example.com/inventory/cones", "https://svcb.example.com/status", "https://svcb.example.com"}；Issuer 信任锚＝Issuer 公钥。

- 机读材料块（A-07，定版增补；与 §2 散文同义，若有出入以散文字面与 JWK 字面为准）：

```json
{
  "key_derivation": {
    "ed25519_seed": "SHA-256(\"s01-validation-vectors:<name>\")",
    "jwk_d": "base64url(seed)",
    "svcC_ec_scalar": "SHA-256(\"s01-validation-vectors:svcC\") mod (n-1) + 1"
  },
  "trusted_config": {
    "wimse_aud_trusted": [
      "https://svcb.example.com/gimme-ice-cream",
      "https://svcb.example.com/inventory/cones",
      "https://svcb.example.com/status",
      "https://svcb.example.com"
    ],
    "issuer_anchor_jwk": {"alg": "Ed25519", "crv": "Ed25519", "kid": "issuer-key", "kty": "OKP", "x": "QH_Zu0pnwyO8xdFQm9upOUFAbpb4nhMrGc29L3uJXDA"}
  }
}
```

## 3. 正例向量（6 条）

### P-01 · Ed25519 签名请求（svcA→svcB，要求签名响应）[修订·因 S1] <!-- id:P-01 -->
- 锚条款：§3 覆盖清单（@method/@path/@query＋存在的必签头）、§3 必备参数（created/expires/nonce/tag＋请求必备 wimse-aud）、§3.3 wimse-sign-response。`@query` 分量值依 RFC 9421 §2.2.7 含前导 `?`。
- 输入消息：
```
GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: svcb.example.com
Workload-Identity-Token: [WIT-A，§2 全文]
Signature-Input: sig1=("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/gimme-ice-cream";wimse-sign-response
Signature: sig1=:qrIGE6wS80/UvhJx96iDiz90OIYmUX8CFO4vOeK/40D7pnukeikqvsYGDs6aqXx099ILxgZliEepCw1P5M7YDg==: [修订·因 S1：随修正基重签]
```
- 签名基：
```
"@method": GET
"@path": /gimme-ice-cream
"@query": ?flavor=vanilla [修订·因 S1：原作 flavor=vanilla]
"workload-identity-token": [WIT-A，§2 全文]
"@signature-params": ("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/gimme-ice-cream";wimse-sign-response
```
- 期望输出：验证通过；且因 wimse-sign-response 为真，服务端义务进入 §3.5「须签响应」分支（与 P-02 配对）。
- 判定式：WIT 先验（Issuer 签名＋exp＞验证时刻）→ 以 cnf.jwk（Ed25519/vec-a-key）按 §3.1 验签 → 覆盖清单与必备参数逐项核 → wimse-aud 与受信任配置逐字比对（§3.2 Simple String Comparison）→ 验证时刻（T0＋60）落在 [created, expires] 内。四步全过为通过；任一失败转 §3.6（400＋wimse-signature-invalid，不区分失败点）。

- 机读锚｜id=P-01; kind=positive; mode=oracle; base=-; expect={outcome: ACCEPT}; stages=all-pass; verify_time=T0+60; sig=literal; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3, 3.3", quote: none-in-entry（A-11 缺项登记，见附录 C.3）}]

### P-02 · 签名响应（svcB→svcA，承 P-01）[修订·因 S1] <!-- id:P-02 -->
- 锚条款：§3 响应覆盖清单（@status＋;req 三件＋存在的 Content-Type/Content-Digest＋Workload-Identity-Token）、§3.4 wimse-req-nonce、§3.5 响应验证。`"@query";req` 分量值依 RFC 9421 §2.2.7 含前导 `?`。
- 输入消息（响应体为 "No ice cream today.\n"，20 字节）：
```
HTTP/1.1 404 Not Found
Content-Type: text/plain
Content-Digest: sha-256=:uJC3qmCc7n6/6w4N2I0vAfj1cd/hTOAhxLEYXmPbNno=:
Workload-Identity-Token: [WIT-B，§2 全文]
Signature-Input: sig1=("@status" "workload-identity-token" "content-type" "content-digest" "@method";req "@path";req "@query";req);created=1795000002;expires=1795000302;nonce="2b8e4f0a9d1c3756e0a2b4c6d8f0a1b3";tag="wimse-workload-to-workload";wimse-req-nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937"
Signature: sig1=:XugjjXCtpc0lkt5QSnjVF/OcQwqhQAqAzuykBUw36FsGV6BmXcMKfY0YZTMTnvpsjIZkmOeTN+PvQEzAb/veDQ==: [修订·因 S1：随修正基重签]

No ice cream today.
```
- 签名基：
```
"@status": 404
"workload-identity-token": [WIT-B，§2 全文]
"content-type": text/plain
"content-digest": sha-256=:uJC3qmCc7n6/6w4N2I0vAfj1cd/hTOAhxLEYXmPbNno=:
"@method";req: GET
"@path";req: /gimme-ice-cream
"@query";req: ?flavor=vanilla [修订·因 S1：原作 flavor=vanilla]
"@signature-params": ("@status" "workload-identity-token" "content-type" "content-digest" "@method";req "@path";req "@query";req);created=1795000002;expires=1795000302;nonce="2b8e4f0a9d1c3756e0a2b4c6d8f0a1b3";tag="wimse-workload-to-workload";wimse-req-nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937"
```
- 期望输出：客户端验证通过并接受响应。
- 判定式：WIT-B 先验 → cnf.jwk 验签 → 客户端核 wimse-req-nonce 存在且等于 P-01 的 nonce（§3.5）→ 重算响应体 Content-Digest 与头值比对（§3）→ 验证时刻（T0＋60）落在响应 [created, expires] 内。全过为通过。
- 互证注记：本条 Content-Digest 计算值与草案 §3.7.1 图 4 示例的头值逐字一致（同体字节），为生成管线与草案示例的一次独立互算对平 [实证·本件生成×草案原文]。

- 机读锚｜id=P-02; kind=positive; mode=oracle; base=-; expect={outcome: ACCEPT}; stages=all-pass（含 BINDING、DIGEST）; verify_time=T0+60; sig=literal; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3, 3.4, 3.5", quote: none-in-entry（A-11 缺项登记，见附录 C.3）}]

### P-03 · ES256 签名请求带体（svcC→svcB）（未修订） <!-- id:P-03 -->
- 锚条款：§3.1 算法由 cnf.jwk.alg 决定、§3 有体必带 Content-Digest 且 Content-Type/Content-Digest 存在即必签。
- 输入消息（体：{"flavor":"vanilla","amount":1}，31 字节）：
```
POST /inventory/cones HTTP/1.1
Host: svcb.example.com
Content-Type: application/json
Content-Digest: sha-256=:TzKXT0tUEfiTFkjRzwE8nCFnQljMuX5xwJaJgJCp+1g=:
Workload-Identity-Token: [WIT-C，§2 全文]
Signature-Input: sig1=("@method" "@path" "@query" "workload-identity-token" "content-type" "content-digest");created=1795000000;expires=1795000300;nonce="c51d7a2e8f093b46a5c1d2e3f4a5b6c7";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/inventory/cones"
Signature: sig1=:n7QUfcBz5ruH3anRYFpW7drn1CInZfV4TZPxlqBIlHg1g78FnRhk7CQudkHN8kNGAHfsBTgIvfHGJMZ8f2QTbQ==:
```
- 签名基：
```
"@method": POST
"@path": /inventory/cones
"@query": ?
"workload-identity-token": [WIT-C，§2 全文]
"content-type": application/json
"content-digest": sha-256=:TzKXT0tUEfiTFkjRzwE8nCFnQljMuX5xwJaJgJCp+1g=:
"@signature-params": ("@method" "@path" "@query" "workload-identity-token" "content-type" "content-digest");created=1795000000;expires=1795000300;nonce="c51d7a2e8f093b46a5c1d2e3f4a5b6c7";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/inventory/cones"
```
- 期望输出：验证通过。
- 判定式：WIT-C 先验 → 按 cnf.jwk.alg＝ES256 以 P-256 公钥验签（签名值为 r‖s 原始拼接）→ 重算体摘要比对 → aud 比对 → 时效窗。全过为通过。
- 互证注记：Content-Digest 值与草案 §3.7.2 图 6 示例头值逐字一致（同体字节）[实证·本件生成×草案原文]。

- 机读锚｜id=P-03; kind=positive; mode=oracle; base=-; expect={outcome: ACCEPT}; stages=all-pass（含 DIGEST）; verify_time=T0+60; sig=literal; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3, 3.1", quote: none-in-entry（A-11 缺项登记，见附录 C.3）}]

### P-04 · CONNECT 例外请求（svcA→svcB）[修订·因 K1] <!-- id:P-04 -->
- 锚条款：§3 CONNECT 例外（MUST 覆盖 @method 与 @authority 代替 @path/@query，MUST NOT 覆盖 @path/@query）；`@authority` 分量值依 RFC 9421 §2.2.3 规范化（hostname 小写、默认端口省略）——请求行与 Host 中的 `svcb.example.com:443` 是消息原形，派生分量值取 `svcb.example.com`（443 为 https 默认端口）；wimse-aud 依 §3.2 部署特定值句取 "https://svcb.example.com"（CONNECT 的 target 为 authority-form，默认 target-URI 规则不直接适用，逐字注明此取法）。
- 输入消息：
```
CONNECT svcb.example.com:443 HTTP/1.1
Host: svcb.example.com:443
Workload-Identity-Token: [WIT-A，§2 全文]
Signature-Input: sig1=("@method" "@authority" "workload-identity-token");created=1795000000;expires=1795000300;nonce="9a0b1c2d3e4f5061728394a5b6c7d8e9";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com"
Signature: sig1=:oQvU3xBjXSOTm2zDvjGMWa/lsOGPyB8+AYxoA9aNd1Dgx2ulyMynph+/lR6d6Vkdl1rXR62kHuaG0sG4q3m2AQ==: [修订·因 K1：随规范化基重签]
```
- 签名基：
```
"@method": CONNECT
"@authority": svcb.example.com [修订·因 K1：原作 svcb.example.com:443]
"workload-identity-token": [WIT-A，§2 全文]
"@signature-params": ("@method" "@authority" "workload-identity-token");created=1795000000;expires=1795000300;nonce="9a0b1c2d3e4f5061728394a5b6c7d8e9";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com"
```
- 期望输出：验证通过。
- 判定式：识别 CONNECT → 覆盖清单按例外组核（@method/@authority 在列、@path/@query 不在列）→ 余同 P-01。

- 机读锚｜id=P-04; kind=positive; mode=oracle; base=-; expect={outcome: ACCEPT}; stages=all-pass（CONNECT 覆盖组）; verify_time=T0+60; sig=literal; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3（CONNECT 例外）", quote: none-in-entry}, {doc: RFC 9421, sec: "2.2.3", quote_head: "the default port", quote_tail: "port is omitted", quote_loc: "§0 总账 K1 行"}]

### P-05 · 无 query 请求（@query 取 "?"）（未修订） <!-- id:P-05 -->
- 锚条款：§3「@query is included even when the request has no query component; in that case its value is ?（RFC 9421 §2.2.7）」。
- 输入消息：
```
GET /status HTTP/1.1
Host: svcb.example.com
Workload-Identity-Token: [WIT-A，§2 全文]
Signature-Input: sig1=("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="13579bdf2468ace013579bdf2468ace0";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/status"
Signature: sig1=:62NICDRikwhl4IlI2ls8cGIACVyuFNtmSZdYOZKiO88AqsKZLQuybOkQx5SQYkREcB0OiU4xT+qn9/hoAj1LAg==:
```
- 签名基：
```
"@method": GET
"@path": /status
"@query": ?
"workload-identity-token": [WIT-A，§2 全文]
"@signature-params": ("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="13579bdf2468ace013579bdf2468ace0";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/status"
```
- 期望输出：验证通过。
- 判定式：同 P-01，其中 @query 分量值必须恰为单个 "?" 字符。

- 机读锚｜id=P-05; kind=positive; mode=oracle; base=-; expect={outcome: ACCEPT}; stages=all-pass; verify_time=T0+60; sig=literal; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "@query is included even", quote_tail: "its value is ?"}]

### P-06 · 多签名共存、按 tag 选 WIMSE 签名 [修订·因 X1（S1 同因）] <!-- id:P-06 -->
- 锚条款：§3「recipients MUST use that tag to find the WIMSE signature; they MUST NOT choose by label」；§5.2 中间盒可附加自有签名。
- 输入消息（sig1 为 other 方的非 WIMSE 签名、标签在前；sig2 为 WIMSE 签名、标签在后）：
```
GET /gimme-ice-cream?flavor=vanilla HTTP/1.1
Host: svcb.example.com
Workload-Identity-Token: [WIT-A，§2 全文]
Signature-Input: sig1=("@method" "@path");created=1795000000;keyid="other-key";tag="example-other", sig2=("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="f0e1d2c3b4a5968778695a4b3c2d1e0f";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/gimme-ice-cream"
Signature: sig1=:C9vDZlqwPqD3dPtkwhQDz0cmpsy0Z2tSE/ewIHjMCdgmdNN7nqrZTLLZqGobMOjswZF43HMaJXGGjFVuRYB5BQ==:, sig2=:Dyr5ErLhw5LmeYIztg6QZmfARn96ucIGuMXUgsyGj9MMc4Y9cQmQ6345/c8/n584kmlk1TfL7xmNVDQKkG7EAw==: [修订·因 X1：sig2 随修正基重签；sig1 不动]
```
- 签名基（sig2，WIMSE）：
```
"@method": GET
"@path": /gimme-ice-cream
"@query": ?flavor=vanilla [修订·因 X1：原作 flavor=vanilla]
"workload-identity-token": [WIT-A，§2 全文]
"@signature-params": ("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="f0e1d2c3b4a5968778695a4b3c2d1e0f";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/gimme-ice-cream"
```
- 签名基（sig1，诱饵；other 密钥签，未修订）：
```
"@method": GET
"@path": /gimme-ice-cream
"@signature-params": ("@method" "@path");created=1795000000;keyid="other-key";tag="example-other"
```
- 期望输出：验证方按 tag 选中 sig2、WIMSE 验证通过；sig1 不进入 WIMSE 判定（其自身在本 profile 外）。
- 判定式：枚举全部签名 → 以 tag＝"wimse-workload-to-workload" 唯一命中 sig2 → 对 sig2 走 P-01 判定式；若实现按标签顺序取 sig1 判定，即落入 N-22。

- 机读锚｜id=P-06; kind=positive; mode=oracle; base=-; expect={outcome: ACCEPT}; stages=all-pass（SELECT 按 tag 命中 sig2）; verify_time=T0+60; sig=literal; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "recipients MUST use that", quote_tail: "NOT choose by label"}]

## 4. 负例集（23 条，逐条对应 MUST 条款）

约定：每条以某正例为基准施加单一变异；「期望」中 400＋类型简写＝HTTP 400、problem type 为 https://iana.org/assignments/http-problem-types#wimse-signature-invalid（草案 §3.6/§7.2.1），且响应不得区分失败点。

- **N-01 漏签 @query**｜基准 P-01，变异：覆盖清单去掉 "@query"。条款：§3「The following derived components MUST be signed: @method, @path, @query」。期望：拒绝，400＋类型。判定式：覆盖清单核对缺项即判负，不进入验签。 <!-- id:N-01 -->
  机读锚｜id=N-01; kind=negative-message; mode=oracle; base=P-01; mutation={op: remove-component, component: "@query"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=COVERAGE; failing_code=E_COVERAGE_MISSING; cascades=[]; verify_time=T0+60; sig=literal（基准字面，变异不重算）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "The following derived components", quote_tail: "@method, @path, @query"}]
- **N-02 CONNECT 覆盖 @path**｜基准 P-04，变异：覆盖清单加入 "@path"（值 /）。条款：§3「For a CONNECT request, senders MUST cover @method and @authority instead of @path and @query, and MUST NOT cover @path or @query」。期望：拒绝，400＋类型。判定式：CONNECT 分支覆盖组核对，@path/@query 在列即判负。 <!-- id:N-02 -->
  机读锚｜id=N-02; kind=negative-message; mode=oracle; base=P-04; mutation={op: add-component, component: "@path"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=COVERAGE; failing_code=E_COVERAGE_FORBIDDEN; cascades=[]; verify_time=T0+60; sig=regen（文字构造，A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "For a CONNECT request,", quote_tail: "cover @path or @query"}]
- **N-03 有体无 Content-Digest**｜基准 P-03，变异：删去 Content-Digest 头及其覆盖项。条款：§3「if the request or response includes a body, the sender MUST include (and the receiver MUST verify) a Content-Digest header」。期望：拒绝，400＋类型。判定式：体存在而 Content-Digest 头缺如即判负。 <!-- id:N-03 -->
  机读锚｜id=N-03; kind=negative-message; mode=oracle; base=P-03; mutation={op: remove-component, component: "content-digest（头与覆盖项）"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=COVERAGE; failing_code=E_DIGEST_MISSING; cascades=[]; verify_time=T0+60; sig=literal（基准字面，变异不重算）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "if the request or", quote_tail: "verify) a Content-Digest header"}]
- **N-04 Content-Digest 与体不符**｜基准 P-03，变异：体改为 {"flavor":"chocolate","amount":1}、头值不变。条款：§3「the receiver MUST compute the Content-Digest value for the message content received and compare it with the Content-Digest value provided」。期望：拒绝，400＋类型。判定式：重算摘要不等即判负（此条同时使签名验证失败，错误面仍须不区分，见 N-17）。 <!-- id:N-04 -->
  机读锚｜id=N-04; kind=negative-message; mode=oracle; base=P-03; mutation={op: set-body, body: "{\"flavor\":\"chocolate\",\"amount\":1}"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=DIGEST; failing_code=E_DIGEST_MISMATCH; cascades=[CRYPTO]; verify_time=T0+60; sig=literal（基准字面，变异不重算）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "the receiver MUST compute", quote_tail: "Content-Digest value provided"}]
- **N-05 缺 expires 参数**｜基准 P-01，变异：Signature-Input 删去 expires。条款：§3「the following signature parameters MUST be included: created, expires, nonce, tag」。期望：拒绝，400＋类型。判定式：必备参数集核对缺项即判负。 <!-- id:N-05 -->
  机读锚｜id=N-05; kind=negative-message; mode=oracle; base=P-01; mutation={op: remove-param, param: "expires"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=PARAMS; failing_code=E_PARAM_MISSING; cascades=[]; verify_time=T0+60; sig=literal（基准字面，变异不重算）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "the following signature parameters", quote_tail: "created, expires, nonce, tag"}]
- **N-06 出现 keyid 参数**｜基准 P-01，变异：参数集加入 keyid="vec-a-key"，签名随之重算（构造方式同正例管线）。条款：§3「The following signature parameters in the Signature-Input header MUST NOT be used: keyid」。期望：该签名不构成合规 WIMSE 签名，验证方不得据此完成 WIMSE 认证（终局：拒绝，400＋类型）。判定式：参数集出现 keyid 即判负，不论签名密码学是否成立。**[确认注记·因 S4]** 此「拒绝」判读已经草案共同作者 Yaron Sheffer 2026-11-07 在 WIMSE 列表确认（"a MUST NOT in any security RFC should be rejected by the recipient"），不再是我方暂记。 <!-- id:N-06 -->
  机读锚｜id=N-06; kind=negative-message; mode=oracle; base=P-01; mutation={op: add-param, param: "keyid=\"vec-a-key\""}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=PARAMS; failing_code=E_PARAM_FORBIDDEN; cascades=[]; verify_time=T0+60; sig=regen（A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "The following signature parameters", quote_tail: "NOT be used: keyid"}]
- **N-07 出现 alg 参数**｜基准 P-01，变异：参数集加入 alg="ed25519"，签名随之重算。条款：§3 同上清单含 alg；§3.1「The alg signature parameter MUST NOT be used」。期望：同 N-06。判定式：参数集出现 alg 即判负。**[确认注记·因 S4]** 同 N-06，判读经作者确认。 <!-- id:N-07 -->
  机读锚｜id=N-07; kind=negative-message; mode=oracle; base=P-01; mutation={op: add-param, param: "alg=\"ed25519\""}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=PARAMS; failing_code=E_PARAM_FORBIDDEN; cascades=[]; verify_time=T0+60; sig=regen（A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3, 3.1", quote_head: "The alg signature parameter", quote_tail: "MUST NOT be used"}]
- **N-08 双签名同 tag**｜基准 P-06，变异：诱饵 sig1 的 tag 改为 "wimse-workload-to-workload"（覆盖与签名随之重算）。条款：§3「If more than one signature has that tag value, the recipient MUST reject the message」。期望：拒绝整条消息，400＋类型。判定式：tag 命中数＞1 即判负，先于任一验签。 <!-- id:N-08 -->
  机读锚｜id=N-08; kind=negative-message; mode=oracle; base=P-06; mutation={op: set-param, member: "sig1", param: "tag=\"wimse-workload-to-workload\""}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=SELECT; failing_code=E_TAG_AMBIGUOUS; cascades=[]; verify_time=T0+60; sig=regen（A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "If more than one", quote_tail: "MUST reject the message"}]
- **N-09 时效窗外**｜基准 P-01，变异：不变异消息，验证时刻取 T0＋3600（晚于 expires＝T0＋300）。条款：§3「Recipients MUST reject signatures that fall outside their validity time window」。期望：拒绝，400＋类型。判定式：验证时刻 ∉ [created, expires] 即判负。 <!-- id:N-09 -->
  机读锚｜id=N-09; kind=negative-message; mode=oracle; base=P-01; mutation={op: set-verify-time, verify_time: "T0+3600"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=WINDOW; failing_code=E_WINDOW_OUTSIDE; cascades=[]（注：该时刻 WIT-A 亦过期，归因隔离弱，源件判定式只判时效窗）; verify_time=T0+3600; sig=literal（同 P-01）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "Recipients MUST reject signatures", quote_tail: "validity time window"}]
- **N-09b 时效窗边界（刚过窗 1 秒）**｜基准 P-01，变异：不变异消息，验证时刻取 T0＋301（expires＝T0＋300，刚过窗 1 秒）。条款：§3「Recipients MUST reject signatures that fall outside their validity time window」。期望：拒绝，400＋类型。判定式：完整判定链（WIT 先验→验签→覆盖与必备参数→wimse-aud 比对）全过、仅验证时刻 ∉ [created, expires] 一项判负。与 N-09（T0＋3600）的分工：N-09 测「远在窗外」，N-09b 测「边界外 1 秒」——两点夹逼 [created, expires] 闭区间右界，防实现把 expires 误作开界或以分钟级粒度取整放行。本条另有一层隔离价值：验证时刻 T0＋301 时 WIT-A 仍在有效期内（exp＝T0＋3600），拒绝**唯一**归因于签名时效窗，不与 WIT 过期混淆（对照 N-20 的探测构造）。 <!-- id:N-09b -->
  机读锚｜id=N-09b; kind=negative-message; mode=contrast; base=P-01; mutation={op: set-verify-time}; evaluations=[{verify_time: "T0+300", expect: {outcome: ACCEPT}}, {verify_time: "T0+301", expect: {outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid, failing_stage: WINDOW, failing_code: E_WINDOW_OUTSIDE, cascades: []}}]; contrast.time_invariant_stages=[WIT, SELECT, PARAMS, COVERAGE, BASE, DIGEST, CRYPTO, AUD]; sig=literal（同 P-01）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "Recipients MUST reject signatures", quote_tail: "validity time window"}]
- **N-10 wimse-aud 规范化变体**｜基准 P-01，变异：wimse-aud 改为 "https://svcb.example.com/gimme-ice-cream/"（尾斜杠），签名随之重算。条款：§3.2「The recipient MUST verify that wimse-aud matches one of the audience values in its trusted configuration using the Simple String Comparison method of RFC 3986 §6.2.1. Strings that differ only by URI normalization ... do not match under that method」。期望：拒绝，400＋类型。判定式：逐字比对不等即判负，不得做规范化等价。 <!-- id:N-10 -->
  机读锚｜id=N-10; kind=negative-message; mode=oracle; base=P-01; mutation={op: set-param, param: "wimse-aud=\"https://svcb.example.com/gimme-ice-cream/\""}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=AUD; failing_code=E_AUD_MISMATCH; cascades=[]; verify_time=T0+60; sig=regen（A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.2", quote_head: "The recipient MUST verify", quote_tail: "of RFC 3986 §6.2.1"}]
- **N-11 请求缺 wimse-aud**｜基准 P-01，变异：参数集删去 wimse-aud，签名随之重算。条款：§3「For requests only, the following signature parameter MUST also be included: wimse-aud」。期望：拒绝，400＋类型。判定式：请求参数集缺 wimse-aud 即判负。 <!-- id:N-11 -->
  机读锚｜id=N-11; kind=negative-message; mode=oracle; base=P-01; mutation={op: remove-param, param: "wimse-aud"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=PARAMS; failing_code=E_PARAM_MISSING; cascades=[]; verify_time=T0+60; sig=regen（A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "For requests only, the", quote_tail: "be included: wimse-aud"}]
- **N-12 签名响应缺 wimse-req-nonce**｜基准 P-02，变异：响应参数集删去 wimse-req-nonce，签名随之重算。条款：§3.4「Every signed response MUST include wimse-req-nonce」；§3 响应必备参数同旨。期望：客户端拒绝该响应。判定式：响应参数集缺 wimse-req-nonce 即判负。 <!-- id:N-12 -->
  机读锚｜id=N-12; kind=negative-message; mode=oracle; base=P-02; mutation={op: remove-param, param: "wimse-req-nonce"}; expect={outcome: CLIENT_REJECT}; failing_stage=PARAMS; failing_code=E_REQNONCE_MISSING; cascades=[]; verify_time=T0+60; sig=regen（A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.4", quote_head: "Every signed response MUST", quote_tail: "MUST include wimse-req-nonce"}]
- **N-13 wimse-req-nonce 不等**｜基准 P-02，变异：wimse-req-nonce 改为 "00000000000000000000000000000000"，签名随之重算。条款：§3.5「the client MUST verify that wimse-req-nonce is present and equals the nonce from the corresponding request」。期望：客户端拒绝该响应。判定式：与触发请求 nonce 逐字不等即判负（防响应串话/重放绑定的承重墙）。 <!-- id:N-13 -->
  机读锚｜id=N-13; kind=negative-message; mode=oracle; base=P-02; mutation={op: set-param, param: "wimse-req-nonce=\"00000000000000000000000000000000\""}; expect={outcome: CLIENT_REJECT}; failing_stage=BINDING; failing_code=E_REQNONCE_MISMATCH; cascades=[]; verify_time=T0+60; sig=regen（A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.5", quote_head: "the client MUST verify", quote_tail: "the corresponding request"}]
- **N-14 要求签响应而响应无签名**｜基准 P-01＋P-02，变异：服务端返回 P-02 的状态行与体、但无任何 Signature/Signature-Input 头。条款：§3.5「The client MUST reject an unsigned response when the request's Signature-Input included wimse-sign-response with the Boolean value true」。期望：客户端拒绝该响应。判定式：请求含 wimse-sign-response（真）∧ 响应无签名 → 判负。 <!-- id:N-14 -->
  机读锚｜id=N-14; kind=negative-message; mode=oracle; base=P-01+P-02; mutation={op: custom-construct, note: "响应侧移除全部 Signature/Signature-Input 头"}; expect={outcome: CLIENT_REJECT}; failing_stage=BINDING; failing_code=E_RESPONSE_UNSIGNED; cascades=[]; verify_time=T0+60; sig=none（无签构造）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.5", quote_head: "The client MUST reject", quote_tail: "Boolean value true"}]
- **N-15 签名算法与 cnf.jwk.alg 不符** [修订·因 T1]｜构造材料（独立计算，非变异重算）：消息与 P-01 同形、WIT 为 WIT-A（cnf 声明 Ed25519/vec-a-key），但签名由 svcC 的 ES256 密钥对同一签名基产生（该 ES256 签名在 svcC 公钥下密码学成立）： <!-- id:N-15 -->
  机读锚｜id=N-15; kind=negative-message; mode=oracle; base=P-01（独立构造）; mutation={op: custom-construct, note: "以 svcC ES256 密钥对 P-01 形签名基产生字面签名"}; expect={outcome: REJECT, http_status: 400, problem_type: wimse-signature-invalid}; failing_stage=CRYPTO; failing_code=E_ALG_BINDING; cascades=[]; verify_time=T0+60; sig=literal; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.1", quote_head: "Recipients MUST verify the", quote_tail: "is not acceptable"}]
```
Signature-Input: sig1=("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="abcdef0123456789abcdef0123456789";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/gimme-ice-cream"
Signature: sig1=:28GmtKZAQJ1w6QtPGGrrrXMhdSgWXCmMbTVIuFNUh+PvOWS1oySwSUAPGhhvoad18zrTZXYh/Dh0ixcHcfB77g==: [修订·因 T1：签名基 @query 行随 S1 修正为 ?flavor=vanilla，本字面值按 RFC 6979 在修正基上重算；原值系在旧基上生成]
签名基：同（修订后）P-01，但 @signature-params 行的 nonce 为 "abcdef0123456789abcdef0123456789"、且无 wimse-sign-response 参数
```
条款：§3.1「Recipients MUST verify the HTTP message signature using the algorithm identified by cnf.jwk.alg and MUST reject the message if that algorithm is not acceptable」。期望：拒绝，400＋类型。判定式：验证只许用 cnf.jwk 指定的算法与密钥；以 ES256 验算「能过」不构成接受理由——算法与密钥绑定以 WIT cnf 为唯一来源。
- **N-16 nonce 熵不足**｜构造：发送方实现被测样本中 nonce 取自 32 bit 空间（如 8 位十六进制短串）。条款：§3「the nonce MUST contain at least 64 bits of entropy」（且 MUST 由密码学安全随机源生成）。期望：发送方一致性判定不合格。判定式：此为发送方用例——验证方无法从单个 nonce 测熵，判定在测试夹具面：采集同实现 N 条请求的 nonce，取值空间或生成分布不足 64 bit 熵即判负。 <!-- id:N-16 -->
  机读锚｜id=N-16; kind=negative-behavior; mode=probe; base=-（发送方样本）; probe={subject: sender; procedure: "见本条构造与判定式"; pass_condition: "同实现 N 条请求 nonce 的取值空间或生成分布不足 64 bit 熵 → NONCONFORMANT"}; expect={outcome: NONCONFORMANT, subject: sender}; failing_code=E_ENTROPY; sig=probe; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "the nonce MUST contain", quote_tail: "64 bits of entropy"}]
- **N-17 错误面泄漏/错码**｜构造：服务端对 WIT 无效与签名无效两种失败分别返回不同 problem type 或可区分文案，或对认证失败返回 401。条款：§3.6「the server MUST return 400 (Bad Request)」「The server MUST NOT distinguish in the response which check failed」；401 为 NOT RECOMMENDED。期望：服务端一致性判定不合格。判定式：两类失败各发一遍，响应状态码与 problem type 须同为 400＋wimse-signature-invalid 且不可区分。 <!-- id:N-17 -->
  机读锚｜id=N-17; kind=negative-behavior; mode=probe; base=-（服务端构造）; probe={subject: server; procedure: "见本条构造与判定式"; pass_condition: "两类失败（WIT 无效／签名无效）各发一遍，响应状态码与 problem type 须同为 400＋wimse-signature-invalid 且不可区分，返回 401 亦判负 → 否则 NONCONFORMANT"}; expect={outcome: NONCONFORMANT, subject: server}; failing_code=E_ERROR_SURFACE; sig=probe; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.6", quote_head: "The server MUST NOT", quote_tail: "which check failed"}]
- **N-18 须签响应却返回成功无签**｜构造：请求含 wimse-sign-response（真），服务端不支持响应签名或本响应不可签，却返回 200＋无签体。条款：§3.5「it MUST NOT return a successful unsigned response; it MUST return an error」；§3.6（不支持→501＋wimse-signed-response-unsupported；支持但本响应不可签→400＋wimse-signed-response-unavailable）。期望：服务端一致性判定不合格（合规行为为 501/400 二选其一，逐字对应情形）。判定式：状态码 ∈ {200} 且无签名即判负；501 与 400 的情形对位再核。 <!-- id:N-18 -->
  机读锚｜id=N-18; kind=negative-behavior; mode=probe; base=-（服务端构造）; probe={subject: server; procedure: "见本条构造与判定式"; pass_condition: "响应状态码 200 且无签名 → NONCONFORMANT（合规行为为 501 不支持／400 不可签，逐情形对位）"}; expect={outcome: NONCONFORMANT, subject: server}; failing_code=E_UNSIGNED_SUCCESS; sig=probe; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.5, 3.6", quote_head: "it MUST NOT return", quote_tail: "MUST return an error"}]
- **N-19 Accept-Signature 请求弱覆盖**｜构造：客户端在请求中发送 Accept-Signature，要求响应仅覆盖 "@status"。条款：§3.5「Accept-Signature MUST NOT be used to request coverage weaker than this profile」。期望：发送方一致性判定不合格；服务端不得据此降低 §3 响应覆盖清单。判定式：Accept-Signature 所列响应分量集 ⊉ §3 响应必签集即判负。 <!-- id:N-19 -->
  机读锚｜id=N-19; kind=negative-behavior; mode=probe; base=-（发送方构造）; probe={subject: sender; procedure: "见本条构造与判定式"; pass_condition: "Accept-Signature 所列响应分量集 ⊉ §3 响应必签集，或服务端据此降低覆盖 → NONCONFORMANT"}; expect={outcome: NONCONFORMANT, subject: sender}; failing_code=E_ACCEPT_SIG_WEAK; sig=probe; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3.5", quote_head: "Accept-Signature MUST NOT be", quote_tail: "weaker than this profile"}]
- **N-20 未先验 WIT 即处理**｜构造：验证方实现先验消息签名、或在全部验证完成前已将消息内容送入业务处理（如先执行后补验）。条款：§3「Recipients ... MUST validate the WIT as specified in Section 5.1.4 of [workload-creds] before validating the HTTP message signature. They MUST ensure that the message is not processed further before it has been fully validated」。期望：验证方一致性判定不合格。判定式：以「WIT 已过期但消息签名密码学成立」的消息探测——处理面出现业务副作用（而非 400 拒绝）即判负；顺序面以实现审查/插桩证据判定。 <!-- id:N-20 -->
  机读锚｜id=N-20; kind=negative-behavior; mode=probe; base=-（验证方构造）; probe={subject: verifier; procedure: "见本条构造与判定式"; pass_condition: "以 WIT 已过期而消息签名成立的消息探测，处理面出现业务副作用 → NONCONFORMANT；顺序面以实现审查/插桩证据判定"}; expect={outcome: NONCONFORMANT, subject: verifier}; failing_code=E_PROCESS_ORDER; sig=probe; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "Recipients ... MUST validate", quote_tail: "been fully validated"}]
- **N-21 CONNECT 的签名响应覆盖 @path;req**｜基准 P-02 形态迁移至 CONNECT 交换，变异：响应覆盖清单加入 "@path";req。条款：§3「When the signed response corresponds to a CONNECT request, senders MUST cover @method;req and @authority;req instead of @path;req and @query;req, and MUST NOT cover @path;req or @query;req」。期望：客户端拒绝该响应签名。判定式：CONNECT 响应分支覆盖组核对，@path;req/@query;req 在列即判负。 <!-- id:N-21 -->
  机读锚｜id=N-21; kind=negative-message; mode=oracle; base=P-02（CONNECT 迁移构造）; mutation={op: add-component, component: "\"@path\";req"}; expect={outcome: CLIENT_REJECT}; failing_stage=COVERAGE; failing_code=E_COVERAGE_FORBIDDEN; cascades=[]; verify_time=T0+60; sig=regen（迁移构造，A-04）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "When the signed response", quote_tail: "cover @path;req or @query;req"}]
- **N-22 按 label 选签名**｜基准 P-06，构造面在验证方：实现以标签顺序（先 sig1）或固定标签名选取待验签名。条款：§3「recipients MUST use that tag to find the WIMSE signature; they MUST NOT choose by label（RFC 9421 §7.2.5）」。期望：验证方一致性判定不合格。判定式：P-06 场景下未选中 sig2（tag 命中者）即判负；与 N-08（发送侧双 tag）互为镜像。 <!-- id:N-22 -->
  机读锚｜id=N-22; kind=negative-behavior; mode=probe; base=P-06（验证方构造面）; probe={subject: verifier; procedure: "见本条构造与判定式"; pass_condition: "P-06 场景下未选中 tag 命中者（sig2），即按 label 选签名 → NONCONFORMANT"}; expect={outcome: NONCONFORMANT, subject: verifier}; failing_code=E_SELECTION_BY_LABEL; sig=probe; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "recipients MUST use that", quote_tail: "NOT choose by label"}]

负例条款对应自查：23 条逐条有 § 出处与 MUST 引文，对应率 23/23；按用例面分列——消息面变异用例 17 条（N-01～N-15、N-09b、N-21），行为面用例 6 条（发送方 N-16/N-19、服务端 N-17/N-18、验证方 N-20/N-22），17＋6＝23 对平，两面不混计。

## 5. 观察项（不入负例计数）

- **集级规则（A-12，定版成文）**：O 前缀条目＝观察项，**不入判定集**、不产判定，只登记；本集判定集＝正例 6＋负例 23＝29 条。此为集级约定，约束本集全部条目与后续版本。

- **O-1 重放缓存为 SHOULD 级**：§3「Recipients MAY maintain a replay cache and SHOULD reject a message whose nonce they have already seen」——非 MUST，故同 nonce 重放不入负例集；但它是本 profile 唯一的重放防线，征评文本中建议 WG 考虑在向量集旁注记其测试方法（跨验证器缓存不共享时重放仍可成功，草案 §3/§5.1 已自述）。 <!-- id:O-1 -->
  机读锚｜id=O-1; kind=observation; judged=false（A-12）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "Recipients MAY maintain a", quote_tail: "they have already seen"}]
- **O-2 草案示例 nonce 与 §3 熵 MUST 的字面对照**：§3.7 示例（图 2/4/6/7）的 nonce 为 "abcd1111" 等 8 位十六进制短串，若按字面即 32 bit，与 §3「MUST contain at least 64 bits of entropy」不符。示例为非规范（non-normative）且 RFC 惯例容许示意值，故不判草案错误；但实现者照示例抄值的风险真实存在，征评建议加编注一句「example nonces are illustrative and do not meet the entropy minimum」。[实证·一手：草案 §3 与 §3.7 直读对位] **[状态更新·因 S2/S5]** 草案共同作者 Sheffer 2026-11-07 已确认采纳并开 issue 增补此注（列表回帖），issue 面亦称另行跟踪——本观察项由「待 WG 回应」转「编辑侧已立项」，条目保留至注记实际入文为止。 <!-- id:O-2 -->
  机读锚｜id=O-2; kind=observation; judged=false（A-12）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3", quote_head: "MUST contain at least", quote_tail: "64 bits of entropy"}]; notes="观察对象为草案 §3.7 示例 nonce 与 §3 熵 MUST 的字面对照；编辑侧已立项（见本条状态更新）"
- **O-3 覆盖 @authority 的非 CONNECT 请求**：§3 对普通请求只说 profile「不覆盖」@authority、未设 MUST NOT（MUST NOT 仅见 CONNECT 分支），故普通请求额外覆盖 @authority 不入负例；其与 wimse-aud 的绑定分工（§5.1）属部署判读面，留征评观察。 <!-- id:O-3 -->
  机读锚｜id=O-3; kind=observation; judged=false（A-12）; clauses=[{doc: draft-ietf-wimse-http-signature-08, sec: "3, 5.1", quote: none-in-entry（A-11 缺项登记，见附录 C.3）}]

## 6. 计数对平

正例 6（P-01～P-06）＋负例 23（N-01～N-22 及 N-09b）＋观察项 3（O-1～O-3）＝32 项，与逐条列名回数一致。本修订版与已发布版差异仅 §0 总账所列 4 条字面修订＋N-06/N-07 确认注记＋O-2 状态注记，其余逐字未动；v4 与 v3 差异仅新增 N-09b 一条（§0 总账 K2 行）及随附计数表述，其余逐字未动。

定版补注（2026-11-13）：本定版与组版稿（hidden/s01-vector-set-v4-draft-2026-11-13.md，03b0b528）的差异仅为：文件头（题名、性质行、前版存置行、锚点层注记、A-10 机读版本头）、§1 A-04 规则行、§2 A-07 机读材料块、§5 A-12 集级规则行、逐条 A-01 ID 锚与机读锚行、§6 本补注、附录 C。29 条向量的输入消息、签名基、Signature 字面值、§2 密钥与 WIT 字面、时间戳、期望与判定式逐字未动——自证方法：定版稿与组版稿逐行 diff，差异行全数落在上列面内，向量本体零差异。

---

# 附录 A · 回贴草稿一（GitHub issue #419 更新帖，英文，未发）

Subject/title: n/a (comment on issue #419)

---

Yaron, thank you for the quick and careful review — and thanks also to @Silentpartnercoding for running the set independently. You were right, and I have regenerated the affected vectors.

**What was wrong.** In three signature bases I wrote the `@query` component value as `flavor=vanilla`, dropping the leading `?` that RFC 9421 Section 2.2.7 requires. My own P-03/P-05 used `?` correctly for the empty query, so the inconsistency was there to be spotted — I should have caught it.

**What changed** (same keys, same parameters, same fixed clock T0 = 1795000000; only the `@query` line and the signature values moved):

- **P-01** — signature base line is now `"@query": ?flavor=vanilla`; signature regenerated:
  `sig1=:qrIGE6wS80/UvhJx96iDiz90OIYmUX8CFO4vOeK/40D7pnukeikqvsYGDs6aqXx099ILxgZliEepCw1P5M7YDg==:`
- **P-02** — `"@query";req: ?flavor=vanilla`; signature regenerated:
  `sig1=:XugjjXCtpc0lkt5QSnjVF/OcQwqhQAqAzuykBUw36FsGV6BmXcMKfY0YZTMTnvpsjIZkmOeTN+PvQEzAb/veDQ==:`
- **P-06** — the WIMSE signature (`sig2`) had the same defect in its base, as the independent run showed; `"@query": ?flavor=vanilla`; `sig2` regenerated:
  `sig2=:Dyr5ErLhw5LmeYIztg6QZmfARn96ucIGuMXUgsyGj9MMc4Y9cQmQ6345/c8/n584kmlk1TfL7xmNVDQKkG7EAw==:`
  The decoy `sig1` covers only `@method`/`@path` and is unchanged.
- **N-15** — this negative case carries a literal signature computed over a P-01-shaped base, so it inherited the same defect. I regenerated it over the corrected base (ES256, RFC 6979 deterministic, svcC key):
  `sig1=:28GmtKZAQJ1w6QtPGGrrrXMhdSgWXCmMbTVIuFNUh+PvOWS1oySwSUAPGhhvoad18zrTZXYh/Dh0ixcHcfB77g==:`
  The case semantics are unchanged: the signature is valid under svcC's key and must still be rejected because `cnf.jwk.alg` binds verification to Ed25519/vec-a-key (Section 3.1).

**What did not change, and why.** Everything else stands as posted. P-03, P-04 and P-05 were re-verified against their published bases and are unaffected (P-03/P-05 already used `?`; P-04 is the CONNECT exception and does not cover `@query`). All negative-case expectations are unchanged; in particular N-06/N-07 (reject on `keyid`/`alg`) are now backed by Yaron's confirmation on the list rather than my reading alone. I re-checked each retained item against the draft text rather than assuming — the full revised set, with the changed lines marked, is available and I will post it in whatever form is most useful.

For reproducibility: the regenerated signatures come from the same independent implementation and the same deterministically derived keys published in the issue; Ed25519 signatures are deterministic, and the ES256 ones are RFC 6979 deterministic, so anyone can recompute them byte-for-byte. I verified that the old signatures fail against the corrected bases and the new ones pass.

On contribution form: noted, I will reach out to the chairs.

— Jiahui Miao (individual participant; affiliation: vertciti)

---

# 附录 B · 回贴草稿二（WIMSE 列表回帖，英文简版，未发）

Subject: Re: [WIMSE] Test vectors for draft-ietf-wimse-http-signature-08 — request for review

---

Hi Yaron, all,

Thank you for the review, on the issue and here — and for answering both questions so directly.

On the vector fix: Yaron was right that in P-01 and P-02 I wrote the `@query` component value without the leading `?` required by RFC 9421 Section 2.2.7. An independent run of the set (reported on the issue) found the same defect in P-06's WIMSE signature. I have regenerated all three over the corrected bases — `"@query": ?flavor=vanilla` — with the same keys, parameters and fixed clock, and also regenerated the literal signature in N-15, which was computed over a P-01-shaped base and inherited the defect; its expected outcome (reject, Section 3.1) is unchanged. The old signatures fail against the corrected bases and the new ones verify; P-03, P-04, P-05 and all other cases were re-checked and are unaffected. Details and the new signature values are on issue #419.

On the two questions: (1) noted and agreed — N-06/N-07 already recorded "reject" for the `keyid`/`alg` MUST NOT parameters, and they now stand on the author's stated intent, not just my reading; (2) thank you for opening an issue to add the example-nonce note (O-2).

On the form of the contribution, I will reach out to the chairs as suggested.

Thanks,
Jiahui Miao (individual participant; affiliation: vertciti)

---

# 附录 C · 机读锚点层处置登记（v4 定版增补）

本附录登记套件设计件 §2.6 锚点需求 A-01～A-12 在本定版的落点与未决项；逐项状态总表随定版回执交付，本附录只载须成文留痕者。

## C.1 锚点行格式

逐条「机读锚｜」行字段：id／kind／mode（oracle｜contrast｜probe）／base／mutation（算子枚举＋对象）／expect（outcome；REJECT 时带 http_status 与 problem_type，响应面为 CLIENT_REJECT，行为面为 NONCONFORMANT＋subject）／failing_stage＋failing_code（套件设计件 §3.2/§3.3 阶段码与失败码）／cascades／verify_time／sig（literal｜regen｜none｜probe）／clauses（草案节号＋MUST 引文首尾词）。正例 expect 恒为 ACCEPT、stages 恒为 all-pass；对照型（N-09b）以 evaluations 列表逐腿给时刻与期望，并附 contrast.time_invariant_stages。

## C.2 A-02 冲突登记（未执行，留待维护面裁定）

- 需求原文：消息内的材料占位符统一为无歧义 token（如 `{{WIT-A}}`），废止含中文标点的 `[WIT-A，§2 全文]` 式（设计件 §2.6 A-02）。
- 冲突点：占位符 `[WIT-A，§2 全文]` 等共 12 处，全数位于正例与 N-15 的输入消息围栏与签名基围栏之内，属向量呈现本体；字面替换即改动向量本体，与本定版「向量本体零改动」约束正面冲突。
- 本轮处置：**保留呈现式原文，不作字面替换**；本登记即冲突留痕，替换与否留待向量集维护面裁定后于下一版本执行。抽取面影响：设计件 §2.2 第 1 步已定「占位符按材料表展开为字面 token」，呈现式保留不阻碍现行抽取；若裁定替换，换版轮须以 diff 自证展开值恒为 §2 WIT 全文、签名语义不变。
- 受影响条目：P-01、P-02、P-03、P-04、P-05、P-06、N-15（占位符出现处）。

## C.3 A-11 缺项登记

下列条目内无草案 MUST 原文引文（仅节号与主题指引），机读锚行 clauses 记 quote=none-in-entry；本轮不拟造引文，补齐须直读草案原文后由维护面落字：

- P-01（§3、§3.3 主题指引）、P-02（§3、§3.4、§3.5 主题指引）、P-03（§3、§3.1 主题指引）；
- P-04 的 RFC 9421 §2.2.3 引文「the default port is omitted」在 §0 总账 K1 行、非条目内，锚行已注明出处（quote_loc）；
- O-3（§3、§5.1 部署判读面，条目内无 MUST 引文）。

## C.4 A-04 再生支适用条目

依 §1 A-04 规则（运行器按 §2 材料再生、确定性签名逐字节可复现）执行的条目：N-02（文字构造、无字面签名）、N-06、N-07、N-08、N-10、N-11、N-12、N-13、N-21（变异后签名未给字面值）。各条机读锚行以 sig=regen 标明。N-14 为无签构造（sig=none），行为面 6 条（N-16～N-20、N-22）为探针构造（sig=probe），均不适用再生支。
