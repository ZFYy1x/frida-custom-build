# Frida 反检测方案对比

| 维度 | `taisuii/rusda` | Florida | 运行时 Hook（文章2） |
|------|-----------------|---------|---------------------|
| **定位** | Level 1 深度版 | Level 1 广度+跟版快 | Level 0 运行时补丁 |
| **核心思路** | 源码 patch + 二进制 post-process | 源码 patch + CI 自动 rebase | 不碰二进制，注入后 hook strcmp/strstr/readlink |
| **字符串隐藏** | XOR 运行时解码 + `.rodata` 倒序 | 编译期静态替换 | 运行时拦截关键词 |
| **线程名** | XOR 编码，运行时解码 | 改 `pool-frida` → `pool-ggbond` | 无 |
| **memfd 名** | `frida-agent` → `jit-cache` | 同左 | 无 |
| **进程名/入口** | `frida-server` → `rusda-server`，`frida_agent_main` → `main` | 同左（`hluda-server` 等） | 不改 |
| **g_set_prgname** | `frida` → `russell`（core + gum 都改） | 只改 core 侧 | 不改 |
| **编译流程** | 手动 patch + `build-android-all.sh` | Fork 官方仓库，CI 24h 内 rebase | 无需编译 |
| **跟版速度** | 慢，作者单人维护 | 快，基本同日 | 不依赖 Frida 版本 |
| **产物** | 4 架构 `.xz`，带 verify-patch 自检 | Release 页直接下载 | 脚本注入，无独立产物 |
| **适用场景** | 动态内存扫描加固（Nesec/libpoison） | 通用场景，90% 默认选择 | 快速绕过，不想重新编译 |
| **短板** | 无 daemon-less，端口 27042 不改 | 无 XOR，`strings` 仍可见部分明文 | 依赖客户端先注入成功，治标不治本 |
