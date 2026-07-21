#!/usr/bin/env python3
"""
Enhanced post-link binary patcher for Frida custom build.
目标：在不破坏协议兼容性的前提下，尽可能减少二进制中的 Frida/Gum 静态特征。

安全可改：
- 函数名/符号名：frida_* → rusda_*
- 纯显示字符串：frida → rusda（等长替换）
- .rodata 中的 Frida/Gum 内部字符串：倒序或等长替换
- 编译路径：../subprojects/... → 简化路径
- FRIDA_* 宏：FRIDA → RUSDA（等长替换）

绝对不能改：
- re.frida.*（D-Bus 服务名）
- Frida.* 开头的 GObject 类型名（协议层）
- frida:rpc（RPC 协议）
- frida_agent_main（入口符号，已在源码层修改）
"""

import lief
import sys
import os
import re


def log_color(msg: str) -> None:
    print(f"\033[1;31;40m{msg}\033[0m")


# GObject 类型名前缀（协议层，绝对不能改）
GOBJECT_TYPE_PREFIXES = (
    "Frida.",
    "Gum.",
    "re.frida.",
)

# .rodata 中需要倒序的字符串（ Rusda 官方已有，保留）
RODATA_REVERSE_STRINGS = [
    "FridaScriptEngine",
    "GLib-GIO",
    "GDBusProxy",
    "GumScript",
]

# .rodata 中需要 frida→rusda 等长替换的纯内部字符串
RODATA_REPLACE_RUSDA = [
    "Frida Agent",
    "frida-zymbiote-",
    "agent-ctrl",
    "frida_server_application_start",
    "frida_server_application_set_device_id",
    "frida_server_application_construct",
    "frida_promise_impl_reject",
    "frida_virtual_stream_write",
    "frida_linux_syscall_trace_service_session_build_event_variant",
    "frida_android_helper_service_handle_request",
    "frida_thread_suspend_scope_enable_co",
    "frida_context != null",
    "FRIDA_AGENT_MODE_SINGLETON",
    "FRIDA_SYSCALL_TRACER_ABI_INVALID",
    "FRIDA_PTRACE_REQUEST_SINGLESTEP",
    "FRIDA_CHILD_ORIGIN_FORK",
    "FRIDA_WEB_SERVICE_FLAVOR_CONTROL",
]

# 编译路径前缀（需要 stripping）
SOURCE_PATH_PREFIXES = [
    "../subprojects/",
    "subprojects/",
]


def is_protected_string(s: str) -> bool:
    """检查字符串是否属于协议层，不能被替换。"""
    for prefix in GOBJECT_TYPE_PREFIXES:
        if s.startswith(prefix):
            return True
    # 保护 re.frida.* 和 Frida.* 类名
    if s.startswith("re.frida.") or s.startswith("Frida."):
        return True
    return False


def patch_symbols(binary: lief.Binary) -> None:
    """扫描并 patch 动态符号表。"""
    if not hasattr(binary, "symbols"):
        return

    for symbol in binary.symbols:
        original = symbol.name

        # 跳过协议层符号
        if original.startswith("re.frida.") or original.startswith("Frida."):
            continue

        # frida_agent_main 已在源码层改为 main，这里再兜底
        if original == "frida_agent_main":
            symbol.name = "main"
            continue

        # frida → rusda（不区分大小写，但保留原大小写形式）
        if "frida" in original.lower():
            # 保护 frida:rpc（源码层已 XOR，这里不应出现，但兜底）
            if "frida:rpc" in original:
                continue
            symbol.name = original.lower().replace("frida", "rusda")
            # 恢复首字母大写（如果原符号是驼峰）
            if original[0].isupper():
                symbol.name = symbol.name.capitalize()


def patch_rodata(binary: lief.Binary) -> None:
    """扫描 .rodata 段，patch 字符串。"""
    for section in binary.sections:
        if section.name != ".rodata":
            continue

        # 先倒序
        for patch_str in RODATA_REVERSE_STRINGS:
            addr_all = section.search_all(patch_str)
            for addr in addr_all:
                patch = [ord(n) for n in list(patch_str)[::-1]]
                log_color(
                    f"[*] RODATA reverse @ {hex(section.file_offset + addr)} "
                    f"orig:{patch_str} new:{''.join(list(patch_str)[::-1])}"
                )
                binary.patch_address(section.file_offset + addr, patch)

        # 再等长替换 frida→rusda
        for patch_str in RODATA_REPLACE_RUSDA:
            addr_all = section.search_all(patch_str)
            if not addr_all:
                continue
            replacement = patch_str.lower().replace("frida", "rusda")
            if len(replacement) != len(patch_str):
                # 长度不匹配，跳过（安全优先）
                log_color(
                    f"[warn] skip {patch_str} -> {replacement}: length mismatch"
                )
                continue
            patch = [ord(c) for c in replacement]
            for addr in addr_all:
                log_color(
                    f"[*] RODATA replace @ {hex(section.file_offset + addr)} "
                    f"orig:{patch_str} new:{replacement}"
                )
                binary.patch_address(section.file_offset + addr, patch)


def strip_source_paths(binary: lief.Binary) -> None:
    """Stripping 编译路径（对 .rodata 中的路径字符串做简化）。"""
    for section in binary.sections:
        if section.name != ".rodata":
            continue

        content = bytes(section.content)
        for prefix in SOURCE_PATH_PREFIXES:
            if prefix.encode("utf-8") in content:
                # 将 ../subprojects/frida-core/src/... 替换为 src/...
                # 注意：只替换路径前缀，保留文件名以维持调试信息可用性
                new_content = content.replace(
                    prefix.encode("utf-8"), b"src/"
                )
                if new_content != content:
                    log_color(
                        f"[*] Strip source path: {prefix} -> src/"
                    )
                    section.content = list(new_content)
                    content = new_content  # 更新 content 继续处理


def patch_sed_byte_replace(input_file: str) -> None:
    """使用 sed 做字节级等长替换（处理 rodata 不方便处理的场景）。"""
    replacements = [
        # 线程名等
        ("gum-js-loop", "russellloop"),
        ("gmain", "rmain"),
        ("gdbus", "rubus"),
        # SONAME 残留
        ("libfrida-gadget-raw", "librusda-gadget-raw"),
        ("libfrida-agent-raw", "librusda-agent-raw"),
        # 其他已知特征
        ("frida-helper", "rusda-helper"),
    ]

    for old, new in replacements:
        if len(old) != len(new):
            log_color(f"[warn] skip sed {old} -> {new}: length mismatch")
            continue
        cmd = f"sed -b -i s/{old}/{new}/g {input_file}"
        os.system(cmd)
        log_color(f"[*] sed replace: {old} -> {new}")


def main(argv: list[str]) -> None:
    if len(argv) < 2:
        print("Usage: topatch.py <input_file>")
        sys.exit(1)

    input_file = argv[1]

    log_color(f"[*] Enhanced topatch: {input_file}")

    binary = lief.parse(input_file)
    if not binary:
        log_color(f"[*] Not ELF/Mach-O/PE, skip")
        sys.exit(1)

    # 1. Patch 符号表
    patch_symbols(binary)
    binary.write(input_file)

    # 2. Patch .rodata
    patch_rodata(binary)
    binary.write(input_file)

    # 3. Strip 编译路径
    strip_source_paths(binary)
    binary.write(input_file)

    # 4. sed 字节替换（线程名、SONAME 等）
    patch_sed_byte_replace(input_file)

    log_color(f"[*] Enhanced topatch finish: {input_file}")


if __name__ == "__main__":
    main(sys.argv)
