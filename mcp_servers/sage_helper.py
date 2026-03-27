from __future__ import annotations

import io
import os
import traceback
from contextlib import redirect_stderr, redirect_stdout

import mcp.types as types
import sympy as sp
from mcp.server.fastmcp import Context, FastMCP


mcp = FastMCP("mcp-sage-helper", log_level="ERROR")


def _base_namespace() -> dict[str, object]:
    ns: dict[str, object] = {
        "__builtins__": __builtins__,
        "sp": sp,
        "symbols": sp.symbols,
        "Matrix": sp.Matrix,
        "Poly": sp.Poly,
        "GF": sp.GF,
        "factor": sp.factor,
        "expand": sp.expand,
        "simplify": sp.simplify,
        "solve": sp.solve,
        "Eq": sp.Eq,
        "mod_inverse": sp.mod_inverse,
    }
    return ns


global_namespace = _base_namespace()


async def _set_working_dir_from_roots(ctx: Context) -> None:
    try:
        roots_result: types.ListRootsResult = await ctx.session.list_roots()
        if roots_result and hasattr(roots_result, "roots") and roots_result.roots:
            uri = str(roots_result.roots[0].uri)
            if uri.startswith("file://"):
                path = os.path.normpath(uri.replace("file://", ""))
                if os.path.normpath(os.getcwd()) != path:
                    os.chdir(path)
    except Exception:
        # Best-effort helper; failures should not break solver usage.
        pass


@mcp.tool()
async def execute_sage(ctx: Context, code: str, reset: bool = False) -> list[types.TextContent]:
    """
    Execute Sage-like symbolic code (SymPy-backed).
    Session state persists between calls unless reset=true.
    """
    global global_namespace
    await _set_working_dir_from_roots(ctx)

    if reset:
        global_namespace = _base_namespace()
        return [types.TextContent(type="text", text="Sage helper session reset.")]

    stdout = io.StringIO()
    stderr = io.StringIO()

    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exec(code, global_namespace)

        out = stdout.getvalue()
        err = stderr.getvalue()
        result = ""
        if out:
            result += f"Output:\n{out}"
        if err:
            result += f"\nErrors:\n{err}"
        if not result:
            try:
                last = code.strip().split("\n")[-1]
                value = eval(last, global_namespace)
                result = f"Result: {repr(value)}"
            except Exception:
                result = "Code executed successfully (no output)"
        return [types.TextContent(type="text", text=result)]
    except Exception:
        return [
            types.TextContent(
                type="text",
                text=f"Error executing code:\n{traceback.format_exc()}",
            )
        ]


@mcp.tool()
async def list_bindings(ctx: Context) -> list[types.TextContent]:
    """List current non-private variables in the Sage helper session."""
    await _set_working_dir_from_roots(ctx)
    visible = {
        k: repr(v)
        for k, v in global_namespace.items()
        if not k.startswith("_") and k != "__builtins__"
    }
    if not visible:
        return [types.TextContent(type="text", text="No session bindings.")]
    body = "\n".join(f"{k} = {v}" for k, v in visible.items())
    return [types.TextContent(type="text", text=body)]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
