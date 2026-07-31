# Security / 安全说明

## 威胁模型（请在运行前阅读）

本工具会请求读取 macOS 钥匙串中的 `Arc Safe Storage` 和 `Chrome Safe Storage` 两项。
**拿到这两个密钥，等价于能够解密本机上对应浏览器的全部密码和 cookie。**
请只在你信任的机器上、从本仓库获取代码后运行；运行前花几分钟通读 `arc_to_chrome.py`
（约 350 行，无依赖注入、无网络调用）是合理的安全实践。

## 数据流

```
Arc 数据库 ──(SQLite backup API 只读拷贝)──> 临时快照(tempfile, 600)
                                              │
                     钥匙串 Arc 密钥解密（内存）│ 钥匙串 Chrome 密钥加密（内存）
                                              ▼
                              Chrome 数据库（merge 前自动备份）
```

- 无网络 I/O：不发起任何网络请求，无遥测。
- 明文不落盘：解密后的密码/cookie 只存在于进程内存；不写日志、不写中转文件。
- 临时文件：`tempfile.TemporaryDirectory` 创建，仅本人可读写，进程退出自动删除。
- 钥匙串材料：派生密钥只保存在内存；若用户在弹窗点「拒绝」，工具会以明确报错退出。
- 备份：`~/arc-to-chrome-backups/<时间戳>/`（700），内含你的真实浏览数据，请妥善保管，
  确认迁移无误后建议删除。

## 已知限制

- Chrome 运行中写入其数据库可能造成数据不一致，因此正式 `merge` 会检测并拒绝；
  请勿用 `--no-backup` 绕过防护，除非你清楚后果。
- 合并 cookies 时「两边都有则保留较新」，可能覆盖 Chrome 现有登录态（有备份可回滚）。

## 报告安全问题

请通过 GitHub Security Advisory（私有）报告，勿开公开 issue 讨论漏洞细节。
