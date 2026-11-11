"""pydecomp - behavior."""
from __future__ import annotations

import re


_RISKY = {
    "anti-vm": re.compile(r"(vmware|virtualbox|vbox|qemu|hyper-v|xen|sandboxie|"
                          r"wine_get_unix_file_name|SbieDll|VBoxService)", re.I),
    "anti-debug": re.compile(r"(ptrace|IsDebuggerPresent|CheckRemoteDebuggerPresent|"
                             r"TracerPid|/proc/self/status|being_debugged)", re.I),
    "anti-sandbox": re.compile(r"(cuckoo|any\.run|joesandbox|wireshark|procmon|"
                               r"processhacker|ollydbg|x64dbg|idaq)", re.I),
    "persistence": re.compile(r"(schtasks|Startup|Run|crontab|systemd|"
                              r"LaunchAgents|reg add|HKEY_CURRENT_USER)", re.I),
    "credential-theft": re.compile(r"(Login Data|wallet\.dat|cookies\.sqlite|"
                                  r"Local State|key3\.db|key4\.db|Exodus|MetaMask|"
                                  r"electrum)", re.I),
    "exfil": re.compile(r"(requests\.post|urllib.*urlopen|socket\.socket|"
                        r"ftp\.|smtplib|telegram|discord)", re.I),
    "expiry": re.compile(r"(datetime\.datetime\.now|time\.time\(\)|expir|"
                         r"license|trial|machine_id|uuid\.getnode|hwid)", re.I),
    "destructive": re.compile(r"(shutil\.rmtree|os\.remove|format\s+[a-z]:|"
                              r"vssadmin|bcdedit|cipher\s+/w)", re.I),
}
