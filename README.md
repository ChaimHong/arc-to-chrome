# arc-to-chrome

把 **Arc 浏览器**的数据迁移到 **Google Chrome** 的小工具（仅支持 macOS）。

原理很简单：Arc 和 Chrome 都是 Chromium，本地数据库格式几乎一样，只是各自用 macOS 钥匙串里不同的密钥（`Arc Safe Storage` / `Chrome Safe Storage`）加密敏感字段。这个脚本做的事就是：**用 Arc 的钥匙解密 → 用 Chrome 的钥匙重新加密 → 合并进 Chrome 的数据库**。

全程离线，没有任何网络请求；**解密后的明文只存在于进程内存中，绝不写入任何文件**。

## 做了什么

- **密码**：读取 Arc 的全部登录密码，在内存中解密后按「网站 + 用户名」去重，只把 Chrome 里没有的合并进去，并用 Chrome 自己的密钥重新加密。解密使用严格 PKCS#7 校验，错密钥/坏密文会被判为失败并跳过，不会把垃圾写进 Chrome。每插入一条，都会立刻用 Chrome 的钥匙回读解密校验（round-trip verify）；**任何一条校验失败都会整批回滚并以非零码退出（fail-closed）**，不留半吊子数据。
- **历史记录**：把 Arc 独有的网址和访问记录合并进 Chrome 的历史，重复的「网址 + 访问时间」自动跳过，并刷新每个网址的访问次数和最后访问时间。
- **Cookies**：合并 Arc 独有的 cookie；两边都有的，**保留较新的一份（可能覆盖 Chrome 现有登录态，合并前会自动备份）**；已过期的直接跳过。写入后同样逐条回读解密校验，失败即整批回滚。
- **合并前自动备份**：正式 `merge` 前会把 Chrome 的 `Login Data` / `History` / `Cookies` 三个文件复制到 `~/arc-to-chrome-backups/<时间戳>/`（目录权限 700）。
- **保护性检查**：正式合并前检测 Chrome 是否在运行，运行中则拒绝写入；`--dry-run` 会把整个流程对着临时副本完整跑一遍，不碰真实数据。

## 没有做什么（以及为什么）

- **不改 Arc 的任何数据**：对 Arc 的数据库只读——库静止时取带锁一致快照，Arc 仍在运行时退化为 `immutable=1` 免锁只读快照（可能略旧几秒，输出中会提示）；两种都不写入 Arc 侧，迁移完 Arc 照旧能用。
- **会话 Cookie 会丢**：Chrome 启动时会清掉「属于上一个会话」的 session cookie，这是 Chrome 自己的机制，任何导入方式都救不回来。
- **第三方（跨站）Cookie 会被 Chrome 丢弃**：Arc 里这类 cookie 的标记组合在 Chrome 看来不合法，加载时会被拒收。丢失的都是 `_ga`、广告投放之类的追踪 cookie，**不影响任何网站的登录状态**。
- **少数网站仍需重新登录**：Google、银行等把登录态绑定在服务端设备上的网站，copy cookie 没用。好在密码已经迁过来了，重新登录就是点一下的事。
- **不迁移**：打开的标签页、书签、扩展、Arc 的画架（Easel）、主题和空间布局。书签建议用 Chrome 自带的 HTML 导入；扩展需在 Chrome 应用商店手动重装。
- **只支持默认的 `Default` 配置文件**（Arc 和 Chrome 都是）。
- **会有钥匙串弹窗**：读取 `Arc Safe Storage` / `Chrome Safe Storage` 密钥时 macOS 会弹窗询问，点「允许」即可。密钥和解密后的明文都只在本机内存中使用，不写入任何文件。
- **浏览器运行时的快照是「尽力而为」**：脚本对数据库快照分两级——库静止（浏览器已退出）时用带锁、可感知 journal 的一致快照；检测到浏览器仍在写入时，自动降级为 `immutable=1` 免锁只读 + `VACUUM INTO`，**不读 journal，可能拿到略旧的视图**，并会在输出中明确提示。`diff` / `--dry-run` 这样用没问题；**正式 `merge` 建议把 Arc 和 Chrome 都退出**，拿完全一致的快照。

## 使用方法

> 仅支持 macOS；需要 Python 3.7+ 和 `pycryptodome`（`pip3 install -r requirements.txt`）。

```bash
# 1. 预览：看看各有多少东西会被合并（只读，浏览器开着也能跑）
python3 arc_to_chrome.py diff

# 2. 演练：对着临时副本完整跑一遍合并流程，不写真实数据
python3 arc_to_chrome.py merge --dry-run

# 3. 完全退出 Chrome（⌘Q），正式合并（自动备份）
python3 arc_to_chrome.py merge

# 也可以只合并部分数据
python3 arc_to_chrome.py merge --what logins,cookies

# 4. 重新打开 Chrome，搞定
```

如果想回滚：退出 Chrome，把 `~/arc-to-chrome-backups/<时间戳>/` 里的三个文件拷回 `~/Library/Application Support/Google/Chrome/Default/` 即可。

## 安全性

- 全程离线：没有网络请求，唯一的系统调用是读钥匙串和读写本地 SQLite 文件。
- 明文不出内存：解密后的密码/cookie 只存在于进程内存；临时快照走 `tempfile`（仅本人可读写），进程结束自动删除，无固定路径残留。
- 数据库快照两级策略：静止库走带锁一致快照（journal-aware）；活跃库自动降级为免锁 immutable 快照（best-effort，输出中会提示），拷贝后一律 `quick_check` 校验、失败重试。
- 合并前自动备份 Chrome 原始文件，可随时回滚。
- 更多威胁模型说明见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE)
