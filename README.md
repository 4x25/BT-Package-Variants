# BT Package Variants

[![Sync upstream releases](https://github.com/4x25/BT-Package-Variants/actions/workflows/sync-releases.yml/badge.svg)](https://github.com/4x25/BT-Package-Variants/actions/workflows/sync-releases.yml)

本仓库通过 GitHub Actions 定时检查 [chinasoul/BT Releases](https://github.com/chinasoul/BT/releases)。发现新的公开 Release 且其中包含 `universal.apk` 后，自动生成并发布 5 个可并存安装的 APK；Release 标题和说明与上游保持一致。

同步任务每小时运行一次，也可在仓库的 **Actions** 页面选择同步工作流，点击 **Run workflow** 手动执行。

## APK 变体

生成文件名与包名相同：

- `com.chinasoul.bt1.apk` — `com.chinasoul.bt1`
- `com.chinasoul.bt2.apk` — `com.chinasoul.bt2`
- `com.chinasoul.bt3.apk` — `com.chinasoul.bt3`
- `com.chinasoul.bt4.apk` — `com.chinasoul.bt4`
- `com.chinasoul.bt5.apk` — `com.chinasoul.bt5`

各变体与官方应用及其他变体的数据相互独立。

## 签名与升级提醒

重打包会改变 APK 签名，因此这些 APK **不能覆盖安装或升级官方版本**，也不能升级由其他密钥签名的同包名 APK。只有包名相同且继续使用本仓库同一签名密钥生成的后续版本才能直接升级；如果签名密钥丢失或更换，需要卸载旧版后重新安装，并会丢失未备份的本地应用数据。

## 来源与免责声明

APK 来源：[chinasoul/BT](https://github.com/chinasoul/BT)。本仓库仅提供自动化重打包与发布流程，与上游项目及其作者无隶属或授权关系。

上游应用、APK、名称、图标、代码及其他内容的权利归原作者或相应权利人所有，不受本仓库 `LICENSE` 对自动化脚本的许可所覆盖。使用者应自行确认其使用和分发行为符合上游许可、适用法律及平台规则，并自行承担安装、数据丢失、兼容性和安全风险。
