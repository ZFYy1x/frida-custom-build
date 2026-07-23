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
    "FridaInjector",
    "GumJS",
    "FridaError",
    "FridaAgent",
    "FridaGadget",
    "FridaServer",
    "GumInterceptor",
    "GumProcess",
    "GumScriptCore",
]

# .rodata 中需要 frida→rusda 等长替换的纯内部字符串
RODATA_REPLACE_RUSDA = [
    # --- agent / server 核心 ---
    "Frida Agent",
    "frida-zymbiote-",
    "agent-ctrl",
    "frida_server_application_start",
    "frida_server_application_set_device_id",
    "frida_server_application_construct",
    "frida_server_application_handle_request",
    "frida_promise_impl_reject",
    "frida_virtual_stream_write",
    "frida_linux_syscall_trace_service_session_build_event_variant",
    "frida_android_helper_service_handle_request",
    "frida_thread_suspend_scope_enable_co",
    "frida_context != null",
    "FRIDA_AGENT_MODE_SINGLETON",
    "FRIDA_AGENT_MODE_SPAWN",
    "FRIDA_AGENT_MODE_ATTACH",
    "FRIDA_AGENT_HELPER_PORT",
    "FRIDA_SYSCALL_TRACER_ABI_INVALID",
    "FRIDA_PTRACE_REQUEST_SINGLESTEP",
    "FRIDA_CHILD_ORIGIN_FORK",
    "FRIDA_CHILD_ORIGIN_VFORK",
    "FRIDA_WEB_SERVICE_FLAVOR_CONTROL",
    "FRIDA_WEB_SERVICE_FLAVOR_POOL",
    "FRIDA_STALKER_MODE_BASIC",
    "FRIDA_STALKER_MODE_DETAILED",
    # --- Gum 内部 ---
    "gum-js-loop",
    "gmain",
    "gdbus",
    "gumjs_loop",
    "gumjs_frida_thread",
    "gumjs_interceptor",
    "gumjs_process",
    "gumjs_module",
    "gumjs_memory",
    "gumjs_file",
    "gumjs_stream",
    "gumjs_script",
    "gumjs_system",
    # --- 线程/进程名 ---
    "frida-helper",
    "frida-inject",
    "frida-gadget",
    "frida-server",
    "frida-agent",
    "frida-eternal-agent",
    "frida-agent-emulated",
    "frida-generate-certificate",
    "frida-gadget-tcp-",
    "frida-gadget-unix",
    "frida-stalker",
    "frida-trace",
    "frida-syscall",
    # --- D-Bus / 协议辅助 ---
    "frida-error-quark",
    "frida-error-quark-",
    "frida_control",
    "frida_p2p",
    "frida_core",
    "frida_gadget",
    "frida_inject",
    # --- 常见内部路径标记 ---
    "frida-core",
    "frida-gum",
    "frida-portal",
    "frida-relay",
]

# 编译路径前缀（需要 stripping）
# 注意：prefix 直接做 bytes.replace，替换为 "src/"（4字节），
# 因此所有 prefix 长度必须一致，否则需单独处理。
# 当前设计为统一替换为 "src/"，仅处理长度相近的前缀。
SOURCE_PATH_PREFIXES = [
    # 本地相对路径 (Unix)
    "../subprojects/",
    "subprojects/",
    # GitHub Actions Ubuntu  runner
    "/home/runner/work/",
    "/home/runner/",
    # GitHub Actions Windows  runner (Git Bash 正斜杠路径)
    "D:/a/",
    # Docker / 通用绝对路径前缀
    "/tmp/",
    # Windows 反斜杠变体（与上述正斜杠长度不同，单独处理）
    # 反斜杠前缀在 strip_source_paths 的第二个循环中处理
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


def _str_at(content: bytes, offset: int, max_len: int = 120) -> str:
    """从 .rodata 字节内容中提取以 offset 开头的可读 ASCII 字符串（到 \0 为止）。"""
    chunk = content[offset:offset + max_len]
    end = chunk.find(b"\x00")
    if end == -1:
        end = max_len
    return chunk[:end].decode("ascii", "ignore")


def patch_rodata(binary: lief.Binary) -> None:
    """扫描 .rodata 段，patch 字符串（协议层字符串受保护，跳过）。"""
    for section in binary.sections:
        if section.name != ".rodata":
            continue

        content = bytes(section.content)

        # 先倒序
        for patch_str in RODATA_REVERSE_STRINGS:
            addr_all = section.search_all(patch_str)
            for addr in addr_all:
                s_at_addr = _str_at(content, addr)
                if is_protected_string(s_at_addr):
                    log_color(
                        f"[*] RODATA reverse skip (protected) @ {hex(section.file_offset + addr)} "
                        f"'{s_at_addr[:40]}'"
                    )
                    continue
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
                s_at_addr = _str_at(content, addr)
                if is_protected_string(s_at_addr):
                    log_color(
                        f"[*] RODATA replace skip (protected) @ {hex(section.file_offset + addr)} "
                        f"'{s_at_addr[:40]}'"
                    )
                    continue
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

        # 第一轮：正斜杠路径前缀
        for prefix in SOURCE_PATH_PREFIXES:
            if prefix.encode("utf-8") in content:
                new_content = content.replace(
                    prefix.encode("utf-8"), b"src/"
                )
                if new_content != content:
                    log_color(
                        f"[*] Strip source path: {prefix} -> src/"
                    )
                    section.content = list(new_content)
                    content = new_content

        # 第二轮：Windows 反斜杠路径变体
        backslash_prefixes = [
            "subprojects\\",
            "D:\\a\\",
            "C:\\a\\",
        ]
        for prefix in backslash_prefixes:
            if prefix.encode("utf-8") in content:
                replacement = prefix.rstrip("\\").replace("\\", "/") + "/"
                new_content = content.replace(
                    prefix.encode("utf-8"), replacement.encode("utf-8")
                )
                if new_content != content:
                    log_color(
                        f"[*] Strip source path (backslash): {prefix} -> {replacement}"
                    )
                    section.content = list(new_content)
                    content = new_content


def patch_sed_byte_replace(input_file: str) -> None:
    """
    使用 sed 做字节级等长替换（处理 rodata 不方便处理的场景）。

    安全性说明：
    - 所有 old/new 对均为等长，不改变 ELF 结构。
    - 替换目标（gum-js-loop / gmain / gdbus / frida-helper 等）在 .rodata/.data
      中均作为独立字符串出现，不作为更长字符串的子串，全局 sed 替换不会产生误伤。
    - 此函数在 patch_rodata 之后执行，覆盖 .rodata 之外的其他段（.data, .dynstr）。
    """
    replacements = [
        # 线程名等（.rodata 中独立字符串，不会误伤）
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


# DT_SONAME / DT_NEEDED 等长映射（libfrida-* → librusda-*）
DYNAMIC_NEEDED_MAP = {
    "libfrida-gadget-raw.so": "librusda-gadget-raw.so",
    "libfrida-agent-raw.so":  "librusda-agent-raw.so",
    "libfrida-core.so":       "librusda-core.so",
    "libfrida-gum.so":        "librusda-gum.so",
    "libfrida-inject-raw.so": "librusda-inject-raw.so",
}

# .comment / .note.gnu.build-id 段名（可安全擦除）
STRIPPABLE_SECTIONS = {
    ".comment",
    ".note.gnu.build-id",
    ".note.gnu.gold-version",
}


def patch_elf_dynamic(binary: lief.Binary) -> None:
    """
    修改 ELF 动态段中的 SONAME / NEEDED 条目，以及擦除 Build ID / .comment 段。

    安全说明：
    - SONAME 改了只影响 readelf -d 的显示；dlopen 用的是文件名，所以需要同步 rename 文件。
    - NEEDED 条目改了后，链接器会按新名字找依赖库。本项目所有库都同步 rename，因此安全。
    - 协议层库（如 libfrida-core.so 本身参与 D-Bus 通信）也改，因为：
      a) 这只是 SONAME，不影响库内部实现；
      b) Android 侧用绝对路径或 rpath 加载，不靠 SONAME 解析。
    """
    if not hasattr(binary, "dynamic_entries"):
        return

    # 1. 修改 DT_SONAME
    soname_entry = binary.get(lief.ELF.DYNAMIC_TAGS.SONAME)
    if soname_entry is not None and soname_entry.name:
        old_soname = soname_entry.name
        new_soname = DYNAMIC_NEEDED_MAP.get(old_soname)
        if new_soname:
            try:
                binary.modify(soname_entry, new_soname)
                log_color(f"[*] DT_SONAME: {old_soname} -> {new_soname}")
            except Exception as e:
                log_color(f"[warn] DT_SONAME patch failed: {e}")

    # 2. 修改 DT_NEEDED
    modified_needed = False
    for entry in binary.dynamic_entries:
        if entry.tag == lief.ELF.DYNAMIC_TAGS.NEEDED and entry.name:
            old_name = entry.name
            new_name = DYNAMIC_NEEDED_MAP.get(old_name)
            if new_name:
                try:
                    binary.modify(entry, new_name)
                    log_color(f"[*] DT_NEEDED: {old_name} -> {new_name}")
                    modified_needed = True
                except Exception as e:
                    log_color(f"[warn] DT_NEEDED patch failed for {old_name}: {e}")

    # 3. 擦除可剥离段（Build ID, .comment）
    for sec_name in STRIPPABLE_SECTIONS:
        sec = binary.get_section(sec_name.encode("utf-8"))
        if sec is not None:
            try:
                sec.content = []
                log_color(f"[*] Strip section: {sec_name}")
            except Exception as e:
                log_color(f"[warn] Strip section {sec_name} failed: {e}")


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

    # 5. ELF 动态段清理（DT_SONAME, DT_NEEDED, Build ID, .comment）
    patch_elf_dynamic(binary)
    binary.write(input_file)

    log_color(f"[*] Enhanced topatch finish: {input_file}")


if __name__ == "__main__":
    main(sys.argv)
