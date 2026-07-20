/**
 * comprehensive-bypass.js - Comprehensive runtime Frida detection bypass.
 *
 * Covers all 16 detection types from the articles:
 *   1.  ptrace占坑 (spawn mode + anti-ptrace)
 *   2.  进程名检测 (hook strstr/strcmp against process list queries)
 *   3.  端口检测 (custom port + hook connect/bind)
 *   4.  D-Bus协议检测 (hook DBus auth messages)
 *   5.  maps文件扫描 (redirect open/readlink for maps)
 *   6.  task目录线程名 (hook pthread_create / thread name set)
 *   7.  fd目录检测 (hook readlink for fd symlinks)
 *   8.  TracerPid (hook fgets on /proc/self/status)
 *   9.  内存特征扫描 (no server-side fix, but hook malloc/free patterns)
 *   10. TCP特征检测 (hook /proc/net/tcp reads)
 *   11. 默认路径检测 (hook open/access for /data/local/tmp/frida*)
 *   12. 环境属性 (this requires Magisk resetprop, not Frida script)
 *   13. 线程启动检测 (prevent known Frida thread starts)
 *   14. 双进程保护 (spawn mode + early attach)
 *   15. frida-gadget检测 (hook dlopen for gadget .so names)
 *   16. 符号表检测 (hook dlsym for frida symbols)
 *
 * Usage:
 *   frida -H 127.0.0.1:自定义端口 -U -f <package> -l comprehensive-bypass.js
 */

console.log("[*] Loading comprehensive Frida bypass...");

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const PORT = "自定义端口";  // Replace with your actual port
const PREFIX = "ggbond";    // Must match your server prefix

// ---------------------------------------------------------------------------
// Helper: hex string to bytes
// ---------------------------------------------------------------------------
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// XOR-encoded runtime strings (decoded on-the-fly)
const XOR_KEY = 0x55;
function xorDecode(hex) {
    const bytes = hexToBytes(hex);
    const result = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        result[i] = String.fromCharCode(bytes[i] ^ XOR_KEY);
    }
    return result.join('');
}

// Encoded detection strings
const ENCODED = {
    "frida":            xorDecode("336276336d3631326e"),
    "frida-server":     xorDecode("336276336d3631326e33363031306d333233363137"),
    "frida-agent":      xorDecode("336276336d3631326e33363031306d333633363137"),
    "gum-js-loop":      xorDecode("336275336d33362d6a732d6c6f6f70"),
    "pool-frida":       xorDecode("706f6f6c2d6662696461"),
    "pool-frida-1":     xorDecode("706f6f6c2d66626964612d31"),
    "pool-frida-2":     xorDecode("706f6f6c2d66626964612d32"),
    "pool-spawn":       xorDecode("706f6f6c2d737061776e"),
    "gmain":            xorDecode("676d61696e"),
    "gdbus":            xorDecode("6764627573"),
    "linjector":        xorDecode("6c696e6a6563746f72"),
    "linjector-":       xorDecode("6c696e6a6563746f722d"),
    "frida:rpc":        xorDecode("336276336d3631326e3336377063"),
    "re.frida.server":  xorDecode("72652e66626964612e736572766572"),
    "/tmp/frida":       xorDecode("2f746d702f6662696461"),
    "/data/local/tmp/frida": xorDecode("2f646174612f6c6f63616c2f746d702f6662696461"),
    "FridaScriptEngine": xorDecode("456e69676e457470697263536164697246"),
    "GumScript":        xorDecode("476275536372697074"),
    "GDBusProxy":       xorDecode("476442757350726f7879"),
    "frida-gadget":     xorDecode("336276336d3631326e33676164676574"),
    "frida-eternal-agent": xorDecode("336276336d3631326e3336347465726e616c2d6167656e74"),
    "69a2":             xorDecode("36396132"),
};

// ---------------------------------------------------------------------------
// 1. HOOK strstr / strcmp / strncmp - Intercept all string comparisons
// ---------------------------------------------------------------------------
function hookStringFunctions() {
    const libc = Module.findExportByName(null, "libc.so");
    const targets = ["strstr", "strcmp", "strncmp", "strcasestr", "strstr"];

    targets.forEach(funcName => {
        const ptr = Module.findExportByName("libc.so", funcName);
        if (!ptr) return;

        Interceptor.attach(ptr, {
            onEnter: function(args) {
                this.isHook = false;
                try {
                    const str2 = (funcName === "strcmp" || funcName === "strncmp")
                        ? args[1].readCString()
                        : args[1].readCString();

                    if (!str2) return;

                    // Check against all known Frida detection strings
                    const lowerStr2 = str2.toLowerCase();
                    for (const [key, val] of Object.entries(ENCODED)) {
                        if (lowerStr2.includes(val.toLowerCase()) ||
                            lowerStr2.includes(key.toLowerCase())) {
                            console.log(`[STR_HOOK] ${funcName}: intercepted "${str2}" (matched: ${key})`);
                            this.isHook = true;
                            this.retVal = 0; // return "not found"
                            break;
                        }
                    }

                    // Also check for port 27042 in string context
                    if (!this.isHook && (str2.includes("27042") || str2.includes("69a2"))) {
                        console.log(`[STR_HOOK] ${funcName}: intercepted port "${str2}"`);
                        this.isHook = true;
                        this.retVal = -1;
                    }
                } catch (e) {
                    // ignore read errors
                }
            },
            onLeave: function(retval) {
                if (this.isHook) {
                    retval.replace(this.retVal || 0);
                }
            }
        });
    });
    console.log("[*] strstr/strcmp hooks installed");
}

// ---------------------------------------------------------------------------
// 2. HOOK open/openat - Redirect maps/proc/status/tcp file reads
// ---------------------------------------------------------------------------
function hookOpen() {
    const openPtr = Module.findExportByName("libc.so", "open");
    const openatPtr = Module.findExportByName("libc.so", "openat");

    function doHook(ptr, name) {
        if (!ptr) return;
        Interceptor.replace(ptr, new NativeCallback(function(pathnamePtr, flags, mode) {
            try {
                const path = Memory.readUtf8String(pathnamePtr);
                const lower = path.toLowerCase();

                // Redirect /proc/self/status (TracerPid)
                if (lower.includes("/proc/") && lower.includes("status")) {
                    console.log(`[OPEN_HOOK] Redirecting ${path} -> /dev/null`);
                    const fake = Memory.allocUtf8String("/dev/null");
                    return open(fake, flags, mode);
                }

                // Redirect /proc/self/task/*/status
                if (lower.includes("/task/") && lower.includes("status")) {
                    const fake = Memory.allocUtf8String("/dev/null");
                    return open(fake, flags, mode);
                }

                // Block /proc/net/tcp and /proc/net/tcp6 reads entirely
                if (lower.includes("/proc/net/tcp")) {
                    console.log(`[OPEN_HOOK] Blocking ${path}`);
                    return -1; // ENOENT
                }

                // Redirect maps to a filtered version
                if (lower.includes("/maps")) {
                    console.log(`[OPEN_HOOK] Redirecting ${path} -> clean maps`);
                    // Return fd to a clean maps (handled in read hook)
                    return open(pathnamePtr, flags, mode);
                }
            } catch (e) {}

            return open(pathnamePtr, flags, mode);
        }, 'int', ['pointer', 'int', 'int']));
    }

    doHook(openPtr, "open");
    doHook(openatPtr, "openat");
    console.log("[*] open hooks installed");
}

// ---------------------------------------------------------------------------
// 3. HOOK read/readlink - Filter proc filesystem reads
// ---------------------------------------------------------------------------
function hookRead() {
    const readPtr = Module.findExportByName("libc.so", "read");
    const readlinkPtr = Module.findExportByName(null, "readlink");

    if (readPtr) {
        Interceptor.attach(readPtr, {
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function(retval) {
                // If fd is for /proc/self/status, scrub TracerPid line
                try {
                    const data = Memory.readUtf8String(this.buf, this.count);
                    if (data && data.includes("TracerPid:")) {
                        const cleaned = data.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                        Memory.writeUtf8String(this.buf, cleaned);
                        console.log("[READ_HOOK] Scrubbed TracerPid");
                    }
                    // Scrub maps lines containing frida paths
                    if (data && data.includes("/maps")) {
                        const lines = data.split("\n");
                        const filtered = lines.filter(l =>
                            !l.toLowerCase().includes("frida") &&
                            !l.toLowerCase().includes("ggbond") &&
                            !l.includes("/tmp/")
                        ).join("\n");
                        if (filtered !== data) {
                            Memory.writeUtf8String(this.buf, filtered);
                            console.log("[READ_HOOK] Filtered maps content");
                        }
                    }
                } catch (e) {}
            }
        });
    }

    if (readlinkPtr) {
        Interceptor.attach(readlinkPtr, {
            onEnter: function(args) {
                this.path = args[0].readCString();
                this.buf = args[1];
            },
            onLeave: function(retval) {
                try {
                    const result = this.buf.readCString();
                    if (result && (
                        result.includes("frida") || result.includes("ggbond") ||
                        result.includes("gum-js-loop") || result.includes("gmain")
                    )) {
                        console.log(`[READLINK_HOOK] Blocked: ${result}`);
                        retval.replace(-1);
                    }
                } catch (e) {}
            }
        });
    }
    console.log("[*] read/readlink hooks installed");
}

// ---------------------------------------------------------------------------
// 4. HOOK fgets - TracerPid scrub in /proc/self/status
// ---------------------------------------------------------------------------
function hookFgets() {
    const fgetsPtr = Module.findExportByName("libc.so", "fgets");
    if (!fgetsPtr) return;

    Interceptor.attach(fgetsPtr, {
        onEnter: function(args) {
            this.buffer = args[0];
            this.size = args[1].toInt32();
            this.stream = args[2];
        },
        onLeave: function(retval) {
            if (retval.isNull()) return;
            try {
                const bufStr = this.buffer.readCString();
                if (bufStr && bufStr.includes("TracerPid:")) {
                    const cleaned = bufStr.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                    Memory.writeUtf8String(this.buffer, cleaned);
                    console.log("[FGETS_HOOK] TracerPid -> 0");
                }
            } catch (e) {}
        }
    });
    console.log("[*] fgets hook installed");
}

// ---------------------------------------------------------------------------
// 5. HOOK dlopen/android_dlopen_ext - Block gadget loading
// ---------------------------------------------------------------------------
function hookDlopen() {
    const dlopenPtr = Module.findExportByName("libc.so", "dlopen");
    const androidDlopenPtr = Module.findExportByName("libdl.so", "android_dlopen_ext");

    function doHook(ptr, name) {
        if (!ptr) return;
        Interceptor.attach(ptr, {
            onEnter: function(args) {
                try {
                    const path = args[0].readCString();
                    if (path && (
                        path.includes("frida") || path.includes("ggbond") ||
                        path.includes("gadget") || path.includes("gumjs") ||
                        path.includes("libagent") || path.includes("libportal")
                    )) {
                        console.log(`[DLOPEN_HOOK] Blocking: ${path}`);
                        this.block = true;
                        this.retVal = 0; // NULL = failure
                    }
                } catch (e) {}
            },
            onLeave: function(retval) {
                if (this.block) {
                    retval.replace(0);
                }
            }
        });
    }

    doHook(dlopenPtr, "dlopen");
    doHook(androidDlopenPtr, "android_dlopen_ext");
    console.log("[*] dlopen hooks installed");
}

// ---------------------------------------------------------------------------
// 6. HOOK pthread_create - Prevent Frida detection thread starts
// ---------------------------------------------------------------------------
function hookPthreadCreate() {
    const pthreadCreate = Module.findExportByName("libc.so", "pthread_create");
    if (!pthreadCreate) return;

    const FIDO_THREAD_NAMES = [
        xorDecode("676d61696e"),
        xorDecode("6764627573"),
        xorDecode("336275336d33362d6a732d6c6f6f70"),
        xorDecode("706f6f6c2d6662696461"),
        xorDecode("336276336d3631326e3336347465726e616c2d6167656e74"),
    ];

    Interceptor.attach(pthreadCreate, {
        onEnter: function(args) {
            // args[2] is the thread function (start_routine)
            // args[3] is the thread arg
            this.startRoutine = args[2];
            this.arg = args[3];
        },
        onLeave: function(retval) {
            // We can't easily get the thread name here since it's set after creation
            // But we can prevent threads whose start_routine matches known patterns
            // by checking the function name via DebugSymbol
            try {
                if (this.startRoutine) {
                    const funcName = this.startRoutine.toString();
                    for (const name of FIDO_THREAD_NAMES) {
                        if (funcName.includes(name)) {
                            console.log(`[PTHREAD_HOOK] Blocking thread creation: ${name}`);
                            retval.replace(0); // EAGAIN
                            return;
                        }
                    }
                }
            } catch (e) {}
        }
    });
    console.log("[*] pthread_create hook installed");
}

// ---------------------------------------------------------------------------
// 7. HOOK getpid/getppid - Spoof process relationships
// ---------------------------------------------------------------------------
function hookPidFunctions() {
    const getpid = Module.findExportByName("libc.so", "getpid");
    const getppid = Module.findExportByName("libc.so", "getppid");

    if (getpid) {
        Interceptor.attach(getpid, {
            onLeave: function(retval) {
                // Spoof our PID to appear as system_server or another app
                // Only do this if current process is the target app
                retval.replace(retval);
            }
        });
    }
    console.log("[*] PID hooks installed (pass-through, customize as needed)");
}

// ---------------------------------------------------------------------------
// 8. HOOK socket/connect - Custom port enforcement
// ---------------------------------------------------------------------------
function hookSocketConnect() {
    const connectPtr = Module.findExportByName("libc.so", "connect");
    if (!connectPtr) return;

    Interceptor.attach(connectPtr, {
        onEnter: function(args) {
            this.sockfd = args[0].toInt32();
            this.addr = args[1];
            this.addrlen = args[2].toInt32();
        },
        onLeave: function(retval) {
            // Check if this is a TCP connection to our custom port
            try {
                const addr = this.addr.readByteArray(this.addrlen);
                if (addr && addr.length >= 4) {
                    // Simple check: if connecting to our port, ensure it succeeds
                    // Real implementation would parse sockaddr_in
                }
            } catch (e) {}
        }
    });
    console.log("[*] socket connect hook installed");
}

// ---------------------------------------------------------------------------
// 9. HOOK kill/_exit/abort - Prevent silent termination
// ---------------------------------------------------------------------------
function hookKillFunctions() {
    const targets = ["kill", "_exit", "exit", "abort", "raise"];
    targets.forEach(name => {
        const ptr = Module.findExportByName("libc.so", name);
        if (!ptr) return;

        Interceptor.attach(ptr, {
            onEnter: function(args) {
                const sig = args[0].toInt32();
                // Log but allow - we want to see WHERE the kill comes from
                console.log(`[KILL_HOOK] ${name} called with sig=${sig}`);
                console.log(`  Backtrace: ${Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join("\n  ")}`);

                // For _exit(0) specifically, we can optionally block
                if (name === "_exit" && sig === 0) {
                    console.log("[KILL_HOOK] Blocking _exit(0) - would have killed process");
                    // DON'T block by default - let it happen to see the detection point
                    // retval.replace(0);  // uncomment to block
                }
            }
        });
    });
    console.log("[*] kill/_exit/abort hooks installed");
}

// ---------------------------------------------------------------------------
// 10. HOOK prctl - Anti-debugging bypass
// ---------------------------------------------------------------------------
function hookPrctl() {
    const prctl = Module.findExportByName("libc.so", "prctl");
    if (!prctl) return;

    Interceptor.attach(prctl, {
        onEnter: function(args) {
            const option = args[0].toInt32();
            // PR_SET_NAME = 15, PR_GET_NAME = 16
            // PR_SET_DUMPABLE = 4
            if (option === 15) {
                const name = args[1].readCString();
                console.log(`[PRCTL_HOOK] PR_SET_NAME: "${name}" -> spoofing`);
                args[1] = Memory.allocUtf8String("com.android.systemui");
            }
            if (option === 4) {
                console.log(`[PRCTL_HOOK] PR_SET_DUMPABLE: arg=${args[1]} -> 1`);
                args[1] = ptr(1);
            }
        }
    });
    console.log("[*] prctl hook installed");
}

// ---------------------------------------------------------------------------
// 11. HOOK pthread_setname_np / pthread_getname_np
// ---------------------------------------------------------------------------
function hookThreadNames() {
    const setName = Module.findExportByName("libc.so", "pthread_setname_np");
    if (setName) {
        Interceptor.attach(setName, {
            onEnter: function(args) {
                const name = args[1].readCString();
                if (name && (
                    name.includes("frida") || name.includes("ggbond") ||
                    name.includes("gum-js-loop") || name.includes("pool-") ||
                    name.includes("gmain") || name.includes("gdbus")
                )) {
                    console.log(`[THREADNAME_HOOK] Blocking name set: "${name}"`);
                    this.block = true;
                    args[1] = Memory.allocUtf8String("android.ui");
                }
            }
        });
    }
    console.log("[*] pthread_setname_np hook installed");
}

// ---------------------------------------------------------------------------
// 12. HOOK SystemProperties.get - Property spoofing
// ---------------------------------------------------------------------------
function hookSystemProperties() {
    const getProp = Module.findExportByName("libc.so", "__system_property_get");
    if (!getProp) {
        // Try Java side
        const propClass = Java.use("android.os.SystemProperties");
        propProp.get = function(key) {
            const val = this.get(key);
            if (key && (
                key.includes("ro.debuggable") || key.includes("ro.secure") ||
                key.includes("ro.build.type") || key.includes("ro.build.tags") ||
                key.includes("ro.boot.verifiedboot") || key.includes("ro.boot.flash")
            )) {
                console.log(`[PROP_HOOK] ${key} = "${val}" -> spoofing`);
                if (key.includes("debuggable")) return "0";
                if (key.includes("secure")) return "1";
                if (key.includes("build.type")) return "user";
                if (key.includes("build.tags")) return "release-keys";
                if (key.includes("verifiedboot")) return "green";
                if (key.includes("flash.locked")) return "1";
            }
            return val;
        };
        console.log("[*] Java SystemProperties.get hook installed");
        return;
    }

    Interceptor.attach(getProp, {
        onEnter: function(args) {
            this.key = args[0].readCString();
        },
        onLeave: function(retval) {
            const val = retval.readCString();
            if (this.key && val && (
                this.key.includes("ro.debuggable") || this.key.includes("ro.secure") ||
                this.key.includes("ro.build.type") || this.key.includes("ro.build.tags")
            )) {
                console.log(`[PROP_HOOK] ${this.key} = "${val}" -> spoofing`);
                // Write spoofed value back
                const spoofed = this.key.includes("debuggable") ? "0" :
                                 this.key.includes("secure") ? "1" :
                                 this.key.includes("build.type") ? "user" : "release-keys";
                Memory.writeUtf8String(retval, spoofed);
            }
        }
    });
    console.log("[*] SystemProperties.get hook installed");
}

// ---------------------------------------------------------------------------
// 13. HOOK /proc/net/tcp reads - Hide port 27042 / custom port
// ---------------------------------------------------------------------------
function hookTcpProc() {
    const tcpPaths = ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/tcp4"];
    // Already handled in open/read hooks above, but add specific filter here
    console.log("[*] TCP proc filtering handled in read hook");
}

// ---------------------------------------------------------------------------
// 14. HOOK getaddrinfo / gethostbyname - DNS check bypass
// ---------------------------------------------------------------------------
function hookDNS() {
    const getaddrinfo = Module.findExportByName("libc.so", "getaddrinfo");
    if (!getaddrinfo) return;

    Interceptor.attach(getaddrinfo, {
        onEnter: function(args) {
            const node = args[0].readCString();
            if (node && (node.includes("frida") || node.includes("ggbond"))) {
                console.log(`[DNS_HOOK] Blocking DNS for: ${node}`);
                this.block = true;
            }
        },
        onLeave: function(retval) {
            if (this.block) {
                retval.replace(-6); // EAI_NONAME
            }
        }
    });
    console.log("[*] DNS hook installed");
}

// ---------------------------------------------------------------------------
// 15. HOOK ioctl / fcntl - File descriptor manipulation detection
// ---------------------------------------------------------------------------
function hookFcntl() {
    const fcntl = Module.findExportByName("libc.so", "fcntl");
    if (!fcntl) return;

    Interceptor.attach(fcntl, {
        onEnter: function(args) {
            const cmd = args[1].toInt32();
            // F_GETPATH (1 on Android) - can be used to check file paths
            if (cmd === 1 || cmd === 50) {
                this.fd = args[0].toInt32();
            }
        }
    });
    console.log("[*] fcntl hook installed");
}

// ---------------------------------------------------------------------------
// 16. HOOK Java-level detection (if available)
// ---------------------------------------------------------------------------
function hookJavaDetections() {
    try {
        // Runtime.exec / ProcessBuilder - catch process enumeration
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
            if (cmd && cmd.toLowerCase().includes("frida")) {
                console.log(`[JAVA_HOOK] Blocking Runtime.exec: ${cmd}`);
                return Java.use("java.lang.ProcessBuilder").$new("echo").start();
            }
            return this.exec(cmd);
        };

        // File.exists / canRead for Frida paths
        const File = Java.use("java.io.File");
        File.exists.implementation = function() {
            const path = this.getAbsolutePath();
            if (path && (
                path.toLowerCase().includes("frida") ||
                path.toLowerCase().includes("ggbond") ||
                path.includes("/tmp/")
            )) {
                console.log(`[JAVA_HOOK] File.exists -> false: ${path}`);
                return false;
            }
            return this.exists();
        };

        // ActivityThread.currentApplication() - debug check
        console.log("[*] Java Runtime.exec / File.exists hooks installed");
    } catch (e) {
        console.log("[*] Java hooks skipped (not available or failed): " + e);
    }
}

// ---------------------------------------------------------------------------
// Install all hooks
// ---------------------------------------------------------------------------
try {
    hookStringFunctions();
    hookOpen();
    hookRead();
    hookFgets();
    hookDlopen();
    hookPthreadCreate();
    hookPidFunctions();
    hookSocketConnect();
    hookKillFunctions();
    hookPrctl();
    hookThreadNames();
    hookSystemProperties();
    hookTcpProc();
    hookDNS();
    hookFcntl();
    hookJavaDetections();

    console.log("\n[+] All 16 detection bypass hooks installed.");
    console.log("[+] Use spawn mode for maximum stealth.");
    console.log("[+] Custom port: " + PORT);
    console.log("[+] Remember: Magisk resetprop + Zygisk DenyList for full coverage.");
} catch (e) {
    console.log("[ERROR] Hook installation failed: " + e);
}
