# Jailbreak Lab

Jailbreak Lab 是一个仅面向自有越狱测试设备的 iOS 环境模拟工具。第一个策略模块用可逆的标记文件和目录，验证目标 App 的越狱文件检测逻辑。

## 安全边界

- helper 只接受编译时白名单内的策略 ID，不接受任意路径。
- live 写入/清理只接受 Jailbreak Lab App 作为直接父进程，拒绝其他进程直接调用 setuid helper。
- 使用 `openat` + `O_EXCL` + `O_NOFOLLOW`，绝不覆盖现有对象，不跟随符号链接。
- 清理时必须验证工具签名内容；不匹配则拒绝删除。
- 不创建任何可执行文件、动态库、LaunchDaemon 或 SSH 服务。
- rootless 布局中，非 Data Volume 路径自动映射到 `/var/jb`。
- 不会为了一个特征自动创建整条父目录链；父目录不存在时如实报错。

## 构建要求

- 完整 Xcode（仅 Command Line Tools 不足以构建 iOS App）
- `ldid`
- `dpkg-deb`

```bash
cd JailbreakLab
make test-helper
make package
```

## GitHub Actions 云构建

不想在 Mac 安装完整 Xcode 时，可以把本目录作为 GitHub 仓库根目录上传。默认分支中的 `.github/workflows/build-deb.yml` 会提供手动构建按钮。

1. 打开 GitHub 仓库的 **Actions** 页面。
2. 选择 **Build jailbreak debs**。
3. 点击 **Run workflow**。
4. 构建成功后，在该次运行页面底部下载 `JailbreakLab-debs-*` Artifact。
5. 解压后会得到 rootless/rootful deb 与 `SHA256SUMS`。

生成的 deb 位于 `Packages/`：

- `com.securitylab.jailbreaklab_1.0.0_rootless.deb`：Dopamine、Fugu15 Rootless、palera1n rootless 等现代 rootless 越狱。
- `com.securitylab.jailbreaklab_1.0.0_rootful.deb`：checkra1n、unc0ver 等 rootful 越狱。

只安装与设备越狱类型对应的一个包。可通过 Sileo/Zebra 或 `dpkg -i` 安装。

## 操作建议

1. 先选择“预演”，检查计划与 rootful/rootless 映射结果。
2. 对测试机快照或备份。
3. 开启“真实写入”并确认隔离设备。
4. 运行待验证 App 的 FileManager、`stat/lstat`、`open/access` 等多层检测。
5. 测试完成后使用“清理工具痕迹”，再卸载 deb。
