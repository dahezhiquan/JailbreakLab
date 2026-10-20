# Jailbreak Lab

Jailbreak Lab 是一个用于自有越狱测试设备的 iOS 环境模拟工具。当前版本只有一个“可疑文件环境”开关：

- 开启：写入白名单中的 73 个越狱特征路径。
- 关闭：只删除内容签名正确、且由本工具创建的文件和目录。

## 安全边界

- helper 只接受编译时白名单，不接受任意路径。
- 仅接受 Jailbreak Lab App 从预期安装位置发起的写入和清理操作。
- 使用 `openat`、`O_EXCL` 和 `O_NOFOLLOW`，不覆盖已有对象，不跟随符号链接。
- `.dylib`、Shell、SSH 等名称只是不可执行的签名占位文件，不包含真实代码或服务。
- 自动识别 rootless/rootful；rootless 环境中的系统路径自动映射到 `/var/jb`。
- 如果目标已存在，工具会保留它；关闭开关时也不会删除它。

## GitHub Actions 构建

1. 将修改推送到 GitHub。
2. 打开仓库的 **Actions** 页面。
3. 选择 **Build jailbreak debs**，点击 **Run workflow**。
4. 构建成功后，在该次运行页面底部下载 `JailbreakLab-debs-*`。
5. 解压后根据越狱类型只安装一个包：

   - `com.securitylab.jailbreaklab_1.1.0_rootless.deb`
   - `com.securitylab.jailbreaklab_1.1.0_rootful.deb`

## 使用

1. 通过 Sileo、Zebra 或 Filza 安装对应的 deb。
2. 打开 **Jailbreak Lab**。
3. 打开“可疑文件环境”开关，然后运行待验证 App 的检测。
4. 测试完成后关闭开关，清理本工具创建的对象。
