#!/usr/bin/env python3
"""
ghidra_decompile.py — Ghidra headless decompiler for CTF reversing.

Runs Ghidra headless to decompile a binary and outputs clean C pseudocode.
Saves per-function decompilation to <challenge_dir>/decompiled/ for selective reading.

Usage:
  # Decompile entire binary (saves to decompiled/ directory)
  python tools/ghidra_decompile.py challenges/MyChall/binary

  # Decompile specific function only
  python tools/ghidra_decompile.py challenges/MyChall/binary --func main

  # List all functions (no decompilation)
  python tools/ghidra_decompile.py challenges/MyChall/binary --list-funcs

  # Output to stdout instead of files
  python tools/ghidra_decompile.py challenges/MyChall/binary --func main --stdout

Environment:
  GHIDRA_HOME: Path to Ghidra installation (default: /opt/ghidra)
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJ_ROOT = Path(__file__).resolve().parent.parent
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
GHIDRA_SCRIPT = PROJ_ROOT / "tools" / "ghidra_scripts" / "DecompileToFiles.java"
GHIDRA_PROJECT_DIR = "/tmp/ghidra_projects"


def ensure_ghidra_script():
    """Create the Ghidra script that does the actual decompilation."""
    script_dir = PROJ_ROOT / "tools" / "ghidra_scripts"
    script_dir.mkdir(parents=True, exist_ok=True)
    script = script_dir / "DecompileToFiles.java"
    if not script.exists():
        script.write_text(GHIDRA_JAVA_SCRIPT, encoding="utf-8")
    return script_dir


GHIDRA_JAVA_SCRIPT = r"""// Ghidra headless script: decompile all functions to individual files
// Output dir is passed as first script argument
//@category CTF
//@keybinding
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileWriter;

public class DecompileToFiles extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputDir = args.length > 0 ? args[0] : "/tmp/ghidra_decompiled";
        String targetFunc = args.length > 1 ? args[1] : "";
        boolean listOnly = args.length > 2 && args[2].equals("--list");

        File outDir = new File(outputDir);
        outDir.mkdirs();

        if (listOnly) {
            // Just list function names and addresses
            File listFile = new File(outDir, "_functions.txt");
            FileWriter lw = new FileWriter(listFile);
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                if (!f.isThunk() && f.getBody().getNumAddresses() > 2) {
                    lw.write(String.format("0x%x %s (%d bytes)\n",
                        f.getEntryPoint().getOffset(), f.getName(),
                        f.getBody().getNumAddresses()));
                }
            }
            lw.close();
            println("[ghidra] Function list written to " + listFile.getPath());
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;

        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.isThunk() || f.getBody().getNumAddresses() <= 2) continue;
            if (!targetFunc.isEmpty() && !f.getName().equals(targetFunc)) continue;

            DecompileResults result = decomp.decompileFunction(f, 30, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String safeName = f.getName().replaceAll("[^a-zA-Z0-9_]", "_");
                String addr = String.format("0x%x", f.getEntryPoint().getOffset());
                File outFile = new File(outDir, safeName + ".c");
                FileWriter fw = new FileWriter(outFile);
                fw.write("// Function: " + f.getName() + " @ " + addr + "\n");
                fw.write("// Size: " + f.getBody().getNumAddresses() + " bytes\n\n");
                fw.write(code);
                fw.close();
                count++;
            }
        }

        decomp.dispose();
        println("[ghidra] Decompiled " + count + " function(s) to " + outputDir);
    }
}
"""


def find_ghidra() -> str:
    """Find analyzeHeadless path."""
    candidates = [
        Path(GHIDRA_HOME) / "support" / "analyzeHeadless",
        Path("/opt/ghidra/support/analyzeHeadless"),
        Path("/usr/local/ghidra/support/analyzeHeadless"),
    ]
    # Also search common locations
    for pattern in ["/opt/ghidra*/support/analyzeHeadless",
                    "/home/*/ghidra*/support/analyzeHeadless"]:
        import glob
        candidates.extend(Path(p) for p in glob.glob(pattern))

    for c in candidates:
        if c.exists():
            return str(c)

    # Try just the command
    if shutil.which("analyzeHeadless"):
        return "analyzeHeadless"

    return ""


def decompile(binary_path: str, func: str = "", list_only: bool = False,
              stdout_mode: bool = False, timeout: int = 120) -> str:
    """Run Ghidra headless decompilation."""
    binary = Path(binary_path).resolve()
    if not binary.exists():
        return f"ERROR: binary not found: {binary}"

    ghidra = find_ghidra()
    if not ghidra:
        return "ERROR: Ghidra not found. Set GHIDRA_HOME or install to /opt/ghidra"

    script_dir = ensure_ghidra_script()

    # Output directory
    output_dir = binary.parent / "decompiled"
    output_dir.mkdir(exist_ok=True)

    # Ghidra project (temporary)
    proj_dir = Path(GHIDRA_PROJECT_DIR)
    proj_dir.mkdir(parents=True, exist_ok=True)
    proj_name = f"ctf_{binary.stem}"

    # Build script args
    script_args = [str(output_dir), func]
    if list_only:
        script_args.append("--list")

    # Clean old project
    for old in proj_dir.glob(f"{proj_name}*"):
        if old.is_file():
            old.unlink()
        elif old.is_dir():
            shutil.rmtree(old, ignore_errors=True)

    cmd = [
        ghidra,
        str(proj_dir), proj_name,
        "-import", str(binary),
        "-overwrite",
        "-scriptPath", str(script_dir),
        "-postScript", "DecompileToFiles.java",
        *script_args,
        "-deleteProject",  # clean up after
    ]

    print(f"[ghidra] Decompiling: {binary.name}", file=sys.stderr)
    if func:
        print(f"[ghidra] Target function: {func}", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace"
        )

        if result.returncode != 0:
            # Extract useful error info
            err_lines = [l for l in result.stderr.splitlines()
                        if "ERROR" in l or "Exception" in l]
            return f"ERROR: Ghidra failed (exit {result.returncode})\n" + "\n".join(err_lines[:10])

    except subprocess.TimeoutExpired:
        return f"ERROR: Ghidra timed out after {timeout}s"

    # Read results
    if list_only:
        list_file = output_dir / "_functions.txt"
        if list_file.exists():
            content = list_file.read_text(encoding="utf-8")
            if stdout_mode:
                return content
            print(content)
            return content
        return "No functions found"

    # Read decompiled files
    if func:
        # Single function
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', func)
        c_file = output_dir / f"{safe_name}.c"
        if c_file.exists():
            content = c_file.read_text(encoding="utf-8")
            if stdout_mode:
                return content
            print(content)
            return content
        return f"Function '{func}' not found in decompilation output"

    # All functions — return summary
    c_files = sorted(output_dir.glob("*.c"))
    if not c_files:
        return "No functions decompiled"

    summary = f"[ghidra] Decompiled {len(c_files)} functions to {output_dir}/\n"
    summary += "Files:\n"
    for f in c_files:
        size = f.stat().st_size
        summary += f"  {f.name} ({size} bytes)\n"
    summary += f"\nRead specific function: python tools/ghidra_decompile.py {binary} --func <name> --stdout"

    if stdout_mode:
        # Concat all (with truncation)
        all_code = []
        total = 0
        MAX_TOTAL = 10000  # ~2500 tokens
        for f in c_files:
            code = f.read_text(encoding="utf-8")
            if total + len(code) > MAX_TOTAL:
                all_code.append(f"\n// [TRUNCATED: {len(c_files) - len(all_code)} more functions in {output_dir}/]")
                break
            all_code.append(code)
            total += len(code)
        return "\n".join(all_code)

    print(summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description="Ghidra headless decompiler for CTF")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--func", "-f", default="", help="Decompile specific function only")
    parser.add_argument("--list-funcs", action="store_true", help="List functions only")
    parser.add_argument("--stdout", action="store_true", help="Output to stdout")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds")
    args = parser.parse_args()

    result = decompile(
        args.binary, func=args.func, list_only=args.list_funcs,
        stdout_mode=args.stdout, timeout=args.timeout
    )
    if result.startswith("ERROR"):
        print(result, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
