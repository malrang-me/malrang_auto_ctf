#!/usr/bin/env python3
"""WSL wrapper for ida-pro-mcp that auto-detects Windows host IP."""
import subprocess
import sys

def get_windows_ip():
    """Get Windows host IP from WSL default gateway."""
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        # "default via 172.21.80.1 dev eth0 ..."
        parts = out.stdout.strip().split()
        if "via" in parts:
            return parts[parts.index("via") + 1]
    except Exception:
        pass
    return "172.21.80.1"  # fallback

if __name__ == "__main__":
    win_ip = get_windows_ip()
    # Forward to ida_pro_mcp with correct Windows IP
    sys.argv = [
        "ida_pro_mcp",
        "--ida-rpc", f"http://{win_ip}:13337"
    ]
    from ida_pro_mcp.server import main
    main()
