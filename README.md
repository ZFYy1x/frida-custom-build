# Custom Frida Build

Automated anti-anti-frida build pipeline for Android ARM64/ARMHF. Forked from upstream Frida, with source and binary patches applied automatically via GitHub Actions.

## What's Patched (Deep Coverage)

### Layer 1 - Source Patches (frida-core + libgum)
- All server/agent process names → `ggbond`
- Thread prefixes: `gum-js-loop` → `ggbond-js`, `pool-frida` → `pool-ggbond`, `gmain` → `ggmain`, `gdbus` → `ggdbus`
- D-Bus directory: `re.frida.server` → `re.ggbond.server`
- RPC channel: `frida:rpc` → Base64 runtime decode
- memfd name: `frida-agent` → `ggbond-memfd`
- linjector pipe: `linjector-<id>` → `ggbondinjector-<ptr><id>`
- Entry symbol: `frida_agent_main` → `ggbond_agent_main` (binary post-process)
- SONAME: `libfrida-*` → `libggbond-*`
- Gadget/tool names: `frida-gadget-*`, `frida-ps`, `frida-push`, etc.
- Temp paths: `/tmp/frida*` → `/tmp/ggbond*`
- XOR runtime decode helper header generated for dynamic strings

### Layer 2 - Binary Post-Process (LIEF + sed)
- `.rodata`/`.data`/`.dynstr` reverse storage: `FridaScriptEngine` → `enignEtpircSadirF`
- Symbol table: all `frida`/`FRIDA` symbols → `ggbond`/`RUSBOND`
- ELF SONAME rewrite
- Byte-level sed replacements for thread/path names (exact-length)
- `.note.gnu.build-id` randomized

### Layer 3 - Build Integration
- `deep-patch-src.py` walks entire source tree recursively
- `anti-anti-frida-deep.py` handles binary layer
- `verify-patch-deep.py` checks raw bytes, LIEF sections, symbol table, `strings`
- GitHub Actions auto-builds arm64 + armhf on every push to master
- Auto-creates GitHub Release with artifacts

## Releases

Each successful build automatically creates a GitHub Release:

```
hluda-<frida-version>-android-arm64.tar.xz
hluda-<frida-version>-android-armhf.tar.xz
```

## Quick Start on Device

```bash
# Push to device
adb push hluda-*/frida-server /data/local/tmp/
adb push hluda-*/frida-agent-*.so /data/local/tmp/

# Run
cd /data/local/tmp && chmod 755 ggbond && ./ggbond -l 127.0.0.1:自定义端口 &

# Connect from PC
frida -H 127.0.0.1:自定义端口 -U -f <your.package.name>
```

## Build Locally

```bash
git clone <your-fork>
cd <your-fork>
bash scripts/apply_patches.sh frida-src arm64
cd frida-src && meson setup build ... && ninja
python scripts/anti-anti-frida.py build/frida-server
python scripts/verify-patch.py build/frida-server
```

## CI Manual Trigger

Go to **Actions -> Build Custom Frida -> Run workflow** and optionally specify a Frida version.

## Runtime Bypass Script

`comprehensive-bypass.js` covers all 16 detection types with Frida instrumentation hooks:

| # | Detection | Hook Target |
|---|-----------|-------------|
| 1 | ptrace 占坑 | spawn 模式 + `ptrace` 拦截 |
| 2 | 进程名 | `strstr`/`strcmp` 全部匹配拦截 |
| 3 | 端口 27042 | `connect`/`bind` 端口检查 |
| 4 | D-Bus 协议 | `strcmp` 拦截认证消息 |
| 5 | maps 扫描 | `open`/`read` 重定向过滤 |
| 6 | task 线程名 | `pthread_create` + `pthread_setname_np` |
| 7 | fd 目录 | `readlink` 拦截 |
| 8 | TracerPid | `fgets`/`read` 写零 |
| 9 | 内存特征 | 配合二进制 patch（见 Layer 2） |
| 10 | TCP 69a2 | `/proc/net/tcp` 读取过滤 |
| 11 | 默认路径 | `open`/`access` 拦截 |
| 12 | 环境属性 | 需 Magisk `resetprop`（脚本不覆盖） |
| 13 | 线程启动检测 | `pthread_create` 拦截已知检测线程 |
| 14 | 双进程保护 | spawn 模式 + 早期 attach |
| 15 | frida-gadget | `dlopen` 拦截 |
| 16 | 符号表 | `dlsym` 拦截 |

## Known Limitations (Cannot Patch via Frida Alone)

These require **Magisk + Zygisk** or **kernel-level** modification:

- `ro.boot.verifiedbootstate` / `ro.boot.flash.locked` — TEE-signed, `resetprop` 可改但 Play Integrity 仍能读取真实值
- KeyMint / KeyStore attestation — 硬件签名，纯软件绕不过
- SELinux enforcing 状态下 `frida-server` 启动限制 — 需 `su -c` 或 Magisk `zygisk`
- 部分 SoC 特定的硬件级反调试（如高通的 TrustZone 监控）

## Files

- `.github/workflows/build.yml` — CI pipeline
- `scripts/deep-patch-src.py` — Layer 1: 源码级全量字符串替换 + XOR helper
- `scripts/anti-anti-frida-deep.py` — Layer 2: LIEF 符号/SONAME/.rodata/.build-id + sed 字节替换
- `scripts/verify-patch-deep.py` — 构建后深度校验
- `scripts/comprehensive-bypass.js` — Layer 3: 运行时 16 类检测 bypass
