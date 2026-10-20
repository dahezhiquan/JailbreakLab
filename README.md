# Jailbreak Lab

Jailbreak Lab 是一个用于自有越狱测试设备的 iOS 环境模拟工具。当前版本提供两个独立开关：

- 可疑文件是否存在：写入或清理白名单中的 73 个越狱特征路径。
- 受限目录是否可写：检查根文件系统是否只读，再将 `/root/`、`/private/`、`/jb/` 逐项尝试设为 `01777`，并以调用 App 的真实 UID 执行临时文件写入与删除测试。

## 安全边界

- helper 只接受编译时白名单，不接受任意路径。
- 仅接受 Jailbreak Lab App 从预期安装位置发起的写入和清理操作。
- 使用 `openat`、`O_EXCL` 和 `O_NOFOLLOW`，不覆盖已有对象，不跟随符号链接。
- `.dylib`、Shell、SSH 等名称只是不可执行的签名占位文件，不包含真实代码或服务。
- 自动识别 rootless/rootful；rootless 环境中的系统路径自动映射到 `/var/jb`。
- 如果目标已存在，工具会保留它；关闭开关时也不会删除它。
- 不会 remount 根文件系统。rootless 下 `/root/` 和 `/jb/` 映射到 `/var/jb` bootstrap；`/private/` 始终是真实路径。
- 开启前记录每个目录的原权限、设备号和 inode；关闭开关或卸载时校验目录身份并恢复原权限。
- `01777` 使目录对所有本地用户可写（sticky bit 限制删除其他用户的文件）。尤其是修改真实 `/private/` 具有高风险，仅应在自有测试机上短时开启。
- Unix 权限可写不代表普通 App 一定能写入；iOS Sandbox 仍可以拒绝目标 App 的访问。

## GitHub Actions 构建

1. 将修改推送到 GitHub。
2. 打开仓库的 **Actions** 页面。
3. 选择 **Build jailbreak debs**，点击 **Run workflow**。
4. 构建成功后，在该次运行页面底部下载 `JailbreakLab-debs-*`。
5. 解压后根据越狱类型只安装一个包：

   - `com.securitylab.jailbreaklab_1.3.0_rootless.deb`
   - `com.securitylab.jailbreaklab_1.3.0_rootful.deb`

## 使用

1. 通过 Sileo、Zebra 或 Filza 安装对应的 deb。
2. 打开 **Jailbreak Lab**。
3. 打开需要的环境开关，然后运行待验证 App 的检测。
4. 测试完成后关闭开关，清理本工具创建的对象并恢复权限。
