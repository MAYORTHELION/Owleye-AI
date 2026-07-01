"""
OwlEye AI - Orchestrator
Starts all agents with one command.
"""

import subprocess
import sys
import time
import os
from pathlib import Path

ROOT = Path(__file__).parent
AGENTS = ROOT / "agents"
PYTHON = sys.executable

def start(name, script, args=None):
    cmd = [PYTHON, str(script)] + (args or [])
    proc = subprocess.Popen(cmd, cwd=str(ROOT))
    print(f"  [+] {name} started (PID {proc.pid})")
    return proc

if __name__ == "__main__":
    print("=" * 55)
    print("  OwlEye AI - Orchestrator")
    print("  Starting all agents...")
    print("=" * 55)

    processes = [
        start("Monitor Agent",       AGENTS / "monitor_agent.py"),
        start("Triage Agent",        AGENTS / "triage_agent.py"),
        start("Investigation Agent", AGENTS / "investigation_agent.py"),
        start("Approval Gate",       AGENTS / "approval_gate.py"),
        start("Containment Agent",   AGENTS / "containment_agent.py"),
        start("Documentation Agent", AGENTS / "documentation_agent.py"),
        start("Flask Dashboard",     ROOT   / "dashboard.py"),
    ]

    print()
    print("  All agents running. Dashboard: http://localhost:5000")
    print("  Press Ctrl+C to stop everything.")
    print("=" * 55)

    try:
        while True:
            time.sleep(5)
            for p in processes:
                if p.poll() is not None:
                    print(f"  [!] Process PID {p.pid} stopped unexpectedly")
    except KeyboardInterrupt:
        print("\n  Shutting down all agents...")
        for p in processes:
            p.terminate()
        print("  All agents stopped. Goodbye.")