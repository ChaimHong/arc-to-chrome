# Security / 安全说明

## 威胁模型（请在运行前阅读）

本工具会请求读取 macOS 钥匙串中的 `Arc Safe Storage` 和 `Chrome Safe Storage` 两项。
**拿到这两个密钥，等价于能够解密本机上对应浏览器的全部密码和 cookie。**
请只在你信任的机器上、从本仓库获取代码后运行；运行前花几分钟通读 `arc_to_chrome.py`
（约 545 行，无依赖注入、无网络调用）是合理的安全实践。

## 数据流

```
Arc 数据库 ──(只读快照)──> 临时快照(tempfile, 600)
                              │
     钥匙串 Arc 密钥解密（内存）│ 钥匙串 Chrome 密钥加密（内存）
                              ▼
                  Chrome 数据库（merge 前自动备份）

快照分两级：
  · 浏览器已退出：带锁读取（journal-aware），事务一致
  · 浏览器运行中：immutable=1 免锁只读 + VACUUM INTO（best-effort，
    不读 journal，可能略旧）；快照后 quick_check 校验、失败重试
```

- 无网络 I/O：不发起任何网络请求，无遥测。
- 明文不落盘：解密后的密码/cookie 只存在于进程内存；不写日志、不写中转文件。
- 临时文件：`tempfile.TemporaryDirectory` 创建，仅本人可读写，进程退出自动删除。
- 解密健壮性：严格 PKCS#7 校验，错密钥/坏密文判为失败并跳过，不会写入 Chrome。
- 写入可回滚：login/cookie 逐条回读解密校验（fail-closed），任一失败整批回滚。
- 钥匙串材料：派生密钥只保存在内存；若用户在弹窗点「拒绝」，工具会以明确报错退出。
- 备份：`~/arc-to-chrome-backups/<时间戳>/`（700），内含你的真实浏览数据，请妥善保管，
  确认迁移无误后建议删除。

## 已知限制

- Chrome 运行中写入其数据库可能造成数据不一致，因此正式 `merge` 检测到 Chrome
  在运行会拒绝执行；**该运行检测无法被绕过**。`--no-backup` 的作用只是跳过自动备份
  （放弃回滚点），与运行检测无关。
- 浏览器运行中取得的快照是 best-effort（见上方数据流），正式迁移请退出 Arc 和 Chrome。
- 合并 cookies 时「两边都有则保留较新」，可能覆盖 Chrome 现有登录态（有备份可回滚）。

## 报告安全问题

请通过 GitHub Security Advisory（私有）报告，勿开公开 issue 讨论漏洞细节。
