# arc-to-chrome

把 **Arc 浏览器**的数据迁移到 **Google Chrome** 的小工具（仅支持 macOS）。

原理很简单：Arc 和 Chrome 都是 Chromium，本地数据库格式几乎一样，只是各自用 macOS 钥匙串里不同的密钥（`Arc Safe Storage` / `Chrome Safe Storage`）加密敏感字段。这个脚本做的事就是：**用 Arc 的钥匙解密 → 用 Chrome 的钥匙重新加密 → 合并进 Chrome 的数据库**，全程本地完成，不经过任何网络。

## 做了什么

- **密码**：读取 Arc 的全部登录密码，解密后按「网站 + 用户名」去重，只把 Chrome 里没有的合并进去，并用 Chrome 自己的密钥重新加密。合并后逐条验证可被 Chrome 正常解密。
- **历史记录**：把 Arc 独有的网址和访问记录合并进 Chrome 的历史，重复的「网址 + 访问时间」自动跳过，并刷新每个网址的访问次数和最后访问时间。
- **Cookies**：合并 Arc 独有的 cookie；两边都有的，保留较新的一份；已过期的直接跳过。
- **不重复导入书签**：工具会先检测——如果你的 Chrome 书签已经包含 Arc 的全部书签（很常见，很多人一开始就是从 Chrome 导入 Arc 的），就什么都不做，避免制造几千条重复。
- **扩展清单**：Arc 的扩展无法自动搬运（Chrome 应用商店政策要求手动点击安装），脚本会列出清单和商店链接，照单点一遍即可。

## 没有做什么（以及为什么）

- **不改 Arc 的任何数据**：对 Arc 的数据库只读，迁移完 Arc 照旧能用。
- **会话 Cookie 会丢**：Chrome 启动时会清掉「属于上一个会话」的 session cookie，这是 Chrome 自己的机制，任何导入方式都救不回来。
- **第三方（跨站）Cookie 会被 Chrome 丢弃**：Arc 里这类 cookie 的标记组合在 Chrome 看来不合法，加载时会被拒收。丢失的都是 `_ga`、广告投放之类的追踪 cookie，**不影响任何网站的登录状态**。
- **少数网站仍需重新登录**：Google、银行等把登录态绑定在服务端设备上的网站，copy cookie 没用。好在密码已经迁过来了，重新登录就是点一下的事。
- **不迁移**：打开的标签页、Arc 的画架（Easel）、主题和空间布局、扩展的自动安装。这些要么是 Arc 私有格式，要么 Chrome 政策不允许。
- **第一次运行会有钥匙串弹窗**：读取 `Arc Safe Storage` / `Chrome Safe Storage` 密钥时 macOS 会弹窗询问，点「允许」即可。密钥只在本机内存中使用，不会写入任何文件。

## 使用方法

> 仅支持 macOS；需要 Python 3 和 `pycryptodome`（`pip3 install pycryptodome`）。
> Chrome 和 Arc 都使用默认的 `Default` 配置文件。

```bash
# 1. 快照 Arc 的数据库（Arc 不用关）
python3 arc_to_chrome.py snapshot

# 2. 先看看有哪些密码会被合并（只看不改）
python3 arc_to_chrome.py diff

# 3. 完全退出 Chrome（⌘Q），然后备份并合并
cp ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data ~/Desktop/backup-Login-Data
cp ~/Library/Application\ Support/Google/Chrome/Default/History    ~/Desktop/backup-History
cp ~/Library/Application\ Support/Google/Chrome/Default/Cookies    ~/Desktop/backup-Cookies
python3 arc_to_chrome.py merge-logins
python3 arc_to_chrome.py merge-history
python3 arc_to_chrome.py merge-cookies

# 4. 重新打开 Chrome，搞定
```

如果想回滚：退出 Chrome，把第 3 步备份的三个文件拷回 `~/Library/Application Support/Google/Chrome/Default/` 即可。

## 安全性

- 全程离线，唯一的系统调用是读钥匙串和读写本地数据库文件。
- 临时快照文件放在 `/tmp` 并设为仅本人可读（600），用完可删。
- 合并前的备份请妥善保管，里面是你的真实浏览数据。

## License

[MIT](LICENSE)
