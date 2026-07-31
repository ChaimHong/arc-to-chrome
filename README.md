# arc-to-chrome

把 **Arc 浏览器**的密码、历史记录和 cookies 迁移到 **Google Chrome** 的小工具（仅支持 macOS）。

全程离线，没有任何网络请求；解密后的明文只存在于内存中，不写入任何文件。

## 使用方法

> 需要 Python 3.7+ 和 `pycryptodome`（`pip3 install -r requirements.txt`）。

```bash
# 1. 预览：看看各有多少东西会被合并（只读，浏览器开着也能跑）
python3 arc_to_chrome.py diff

# 2. 演练：对着临时副本完整跑一遍合并流程，不写真实数据
python3 arc_to_chrome.py merge --dry-run

# 3. 完全退出 Chrome（⌘Q），正式合并（会自动备份 Chrome 原文件）
python3 arc_to_chrome.py merge

# 也可以只合并部分数据
python3 arc_to_chrome.py merge --what logins,cookies

# 4. 重新打开 Chrome，搞定
```

运行时 macOS 会弹钥匙串授权框，点「允许」即可。正式合并前建议把 Arc 也退出，数据更完整。

想回滚：退出 Chrome，把 `~/arc-to-chrome-backups/<时间戳>/` 里的三个文件拷回
`~/Library/Application Support/Google/Chrome/Default/` 即可。

## 安全性

- 全程离线：唯一的系统调用是读钥匙串和读写本地数据库文件。
- 明文不出内存：解密后的密码/cookie 不写入任何文件。
- 合并前自动备份 Chrome 原始文件，可随时回滚。
- 更多说明见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE)
