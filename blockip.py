import subprocess

def blockIP(ip):
    try:
        subprocess.run(
            [
                "sudo",
                "iptables",
                "-A",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ],
            check=True
        )

        print(f"[RESPONSE] Blocked {ip}")

    except subprocess.CalledProcessError as e:
        print(f"Failed to block {ip}: {e}")