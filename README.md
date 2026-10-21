# Jailbreak Lab

Jailbreak Lab 是一个用于自有越狱测试设备的 iOS 环境模拟工具。当前版本提供七个独立开关：

- HJ01 可疑文件是否存在：写入或清理白名单中的 73 个越狱特征路径。
- HJ02 受限目录是否可写：检查根文件系统是否只读，再将 `/root/`、`/private/`、`/jb/` 逐项尝试设为 `01777`，并以调用 App 的真实 UID 执行临时文件写入与删除测试。
- HJ03 被调试状态：仅在所选 App 查询当前 PID 的 `sysctl` 结果中设置 `P_TRACED`，其他查询原样透传。
- HJ04 异常符号链接：将 7 个固定关键目录的原内容移到同级工具专用备份，再在原路径创建指向备份的符号链接。
- HJ05 / HJ06 已加载镜像与工具特征：注入名称含 `Shadow` 的 dylib，并注册 `ShadowRuleset/internalDictionary`，一个开关同时构造两项证据。
- IOS_INJ_01 Runtime Hook 检测：向所选目标注入独立 dylib，将 `-[NSProcessInfo processName]` 的 IMP 替换为位于该 dylib 内的转发实现，返回值保持不变。
- IOS_INJ_02 MSHookFunction 检测：向所选目标注入独立 dylib，通过设备注入引擎的 `MSHookFunction` inline hook `getpid`，并继续返回原始 PID。

## 安全边界

- helper 只接受编译时白名单，不接受任意路径。
- 仅接受 Jailbreak Lab App 从预期安装位置发起的写入和清理操作。
- 使用 `openat`、`O_EXCL` 和 `O_NOFOLLOW`，不覆盖已有对象，不跟随符号链接。
- `.dylib`、Shell、SSH 等名称只是不可执行的签名占位文件，不包含真实代码或服务。
- 自动识别 rootless/rootful；rootless 环境中的系统路径自动映射到 `/var/jb`。
- 可疑文件已存在时会保留；符号链接策略会保留原目录的内容和 inode，恢复时严格校验。
- 不会 remount 根文件系统。rootless 下 `/root/` 和 `/jb/` 映射到 `/var/jb` bootstrap；`/private/` 始终是真实路径。
- 开启前记录每个目录的原权限、设备号和 inode；关闭开关或卸载时校验目录身份并恢复原权限。
- `01777` 使目录对所有本地用户可写（sticky bit 限制删除其他用户的文件）。尤其是修改真实 `/private/` 具有高风险，仅应在自有测试机上短时开启。
- Unix 权限可写不代表普通 App 一定能写入；iOS Sandbox 仍可以拒绝目标 App 的访问。
- 符号链接策略会暂时改变 `/Applications`、`/Library/Ringtones`、`/Library/Wallpaper`、`/usr/include`、`/usr/libexec`、`/usr/share`、`/var/lib/undecimus/apt` 的目录项类型。rootless 下非 `/var` 路径映射到 bootstrap。
- 关闭开关或卸载时会验证符号链接目标、设备号和 inode 后恢复；若身份不匹配则拒绝修改。
- 安装包依赖 `mobilesubstrate`；Dopamine 会通过该依赖安装 ElleKit。首次安装注入引擎后，按包管理器提示重启用户空间。
- HJ03 和 HJ05/HJ06 开关只为当前选择的 Bundle ID 创建独立过滤配置，并结束 `.app` 目录名和可执行名均精确匹配的目标进程；重新打开该 App 后生效。
- HJ03 不启动调试器，只修改目标 App 内部的指定查询结果；关闭后需重启目标 App 恢复原始 `sysctl` 入口。
- HJ05/HJ06 进程已运行时注册的类无法动态移除，关闭后需重启目标 App。
- Runtime Hook 开关使用独立过滤配置，只影响当前选择的 Bundle ID。关闭时仅删除本工具签名匹配的配置；目标 App 重新启动后恢复原始 IMP。
- MSHookFunction 开关使用第三份独立过滤配置，只影响当前选择的 Bundle ID。关闭后目标 App 重启才会恢复 `getpid` 原始入口。
- App 选择器只列出 `/var/containers/Bundle/Application` 下的第三方 App，并排除 Jailbreak Lab 自身。目标参数经过字符、长度和路径分隔符校验；关闭时不会注册模拟类。

## GitHub Actions 构建

1. 将修改推送到 GitHub。
2. 打开仓库的 **Actions** 页面。
3. 选择 **Build jailbreak debs**，点击 **Run workflow**。
4. 构建成功后，在该次运行页面底部下载 `JailbreakLab-debs-*`。
5. 解压后根据越狱类型只安装一个包：

   - `com.securitylab.jailbreaklab_1.10.0_rootless.deb`
   - `com.securitylab.jailbreaklab_1.10.0_rootful.deb`

## 使用

1. 通过 Sileo、Zebra 或 Filza 安装对应的 deb。
2. 打开 **Jailbreak Lab**。
3. 在注入策略区域选择检测 App，再打开需要的环境开关并运行检测。
4. 测试完成后关闭开关，清理本工具创建的对象并恢复权限。

MSHookFunction 开关的检测契约是 `functionAddress = (const void *)&getpid`、
`symbol = @"getpid"`。检测程序传入其他函数地址时，不会命中这个构造环境。
