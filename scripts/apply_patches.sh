#!/bin/bash
set -euo pipefail

SRC_DIR="$1"
ARCH="$2"

echo "=== Applying source patches to $SRC_DIR (arch: $ARCH) ==="

# Patch 1: g_set_prgname in frida-glue.c (thread prefix)
GLUE_FILE="$SRC_DIR/src/frida-glue.c"
if [ -f "$GLUE_FILE" ]; then
  if ! grep -q 'g_set_prgname.*ggbond' "$GLUE_FILE"; then
    echo 'Patching frida-glue.c: g_set_prgname'
    sed -i '/^g_set_prgname/i #ifdef HAVE_SETPRNAME\n  g_set_prgname ("ggbond");\n#endif' "$GLUE_FILE" || true
  fi
fi

# Patch 2: memfd name in linux.vala
LINUX_VALA="$SRC_DIR/lib/base/linux.vala"
if [ -f "$LINUX_VALA" ]; then
  if grep -q 'MEMFD_CREATE.*name' "$LINUX_VALA"; then
    echo 'Patching linux.vala: memfd name -> jit-cache'
    sed -i 's/MEMFD_CREATE, name/MEMFD_CREATE, "jit-cache"/' "$LINUX_VALA"
  fi
fi

# Patch 3: server name in server.vala
SERVER_VALA="$SRC_DIR/server/server.vala"
if [ -f "$SERVER_VALA" ]; then
  if grep -q '"frida-server"' "$SERVER_VALA"; then
    echo 'Patching server.vala: server name'
    sed -i 's/"frida-server"/"ggbond"/' "$SERVER_VALA"
  fi
  if grep -q '"frida-agent' "$SERVER_VALA"; then
    echo 'Patching server.vala: agent name pattern'
    sed -i 's/"frida-agent-/$UUID-/g' "$SERVER_VALA" || true
  fi
  if grep -q '"re.frida.server"' "$SERVER_VALA"; then
    echo 'Patching server.vala: D-Bus directory'
    sed -i 's/"re.frida.server"/"re.ggbond.server"/' "$SERVER_VALA"
  fi
fi

# Patch 4: RPC Base64 in rpc.vala
RPC_VALA="$SRC_DIR/lib/base/rpc.vala"
if [ -f "$RPC_VALA" ]; then
  if grep -q '"frida:rpc"' "$RPC_VALA"; then
    echo 'Patching rpc.vala: frida:rpc -> Base64'
    sed -i 's/"frida:rpc"/(string) GLib.Base64.decode("ZnJpZGE6cnBj=")/' "$RPC_VALA"
  fi
fi

# Patch 5: linux helper pipe name
HELPER_GLUE="$SRC_DIR/src/linux/frida-helper-backend-glue.c"
if [ -f "$HELPER_GLUE" ]; then
  if grep -q 'linjector-' "$HELPER_GLUE"; then
    echo 'Patching helper glue: linjector pipe name'
    sed -i 's/linjector-%u/%p%u/' "$HELPER_GLUE"
  fi
fi

# Patch 6: agent SO name randomization (Linux host session)
HOST_SESSION="$SRC_DIR/src/linux/linux-host-session.vala"
if [ -f "$HOST_SESSION" ]; then
  if grep -q 'frida-agent-' "$HOST_SESSION"; then
    echo 'Patching linux-host-session.vala: agent SO name'
    sed -i 's/frida-agent-/ggbond-agent-/' "$HOST_SESSION"
  fi
fi

# Patch 7: entry symbol frida_agent_main -> main (all platforms)
echo 'Patching entry symbols: frida_agent_main -> main'
find "$SRC_DIR/src" -name '*.c' -o -name '*.vala' | xargs grep -l 'frida_agent_main' 2>/dev/null | while read -r f; do
  sed -i 's/frida_agent_main/main/g' "$f"
done

# Patch 8: Additional thread name patterns
for f in "$SRC_DIR/src/"*.c "$SRC_DIR/src/"*.vala "$SRC_DIR/lib/base/"*.vala; do
  [ -f "$f" ] || continue
  if grep -q 'gmain\|gdbus' "$f" 2>/dev/null; then
    echo "Patching thread names in $f"
    sed -i 's/gmain/ggmain/g' "$f" || true
    sed -i 's/gdbus/ggbus/g' "$f" || true
  fi
done

echo "=== Source patches applied ==="
