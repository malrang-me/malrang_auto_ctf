from __future__ import annotations

from typing import Any

import mcp.types as types
from mcp.server.fastmcp import FastMCP
from pycryptosat import Solver


mcp = FastMCP("mcp-cryptominisat-helper", log_level="ERROR")


@mcp.tool()
def solve_cnf(
    clauses: list[list[int]],
    xor_clauses: list[dict[str, Any]] | None = None,
    assumptions: list[int] | None = None,
    threads: int = 1,
) -> list[types.TextContent]:
    """
    Solve CNF/XOR SAT with CryptoMiniSat (pycryptosat).

    xor_clauses format:
    [
      {"vars": [1,2,3], "rhs": 0},
      {"vars": [4,5], "rhs": 1}
    ]
    """
    try:
        solver = Solver(threads=max(1, int(threads)))

        for clause in clauses:
            if not clause:
                return [types.TextContent(type="text", text="Invalid clause: empty clause list entry.")]
            solver.add_clause([int(x) for x in clause])

        if xor_clauses:
            for xc in xor_clauses:
                xs = [int(x) for x in xc.get("vars", [])]
                rhs = bool(int(xc.get("rhs", 0)))
                if not xs:
                    return [types.TextContent(type="text", text="Invalid xor clause: vars is empty.")]
                solver.add_xor_clause(xs, rhs)

        assumps = [int(x) for x in (assumptions or [])]
        sat, model = solver.solve(assumptions=assumps)

        if sat is True:
            # model[0] is dummy; positive literal means True.
            result = {
                "sat": True,
                "num_vars": len(model) - 1 if model else 0,
                "true_lits": [i for i in range(1, len(model)) if model[i]],
            }
            return [types.TextContent(type="text", text=str(result))]
        if sat is False:
            return [types.TextContent(type="text", text=str({"sat": False}))]
        return [types.TextContent(type="text", text=str({"sat": None, "message": "Unknown/timeout"}))]
    except Exception as exc:
        return [types.TextContent(type="text", text=f"solve_cnf error: {type(exc).__name__}: {exc}")]


@mcp.tool()
def solve_dimacs(dimacs: str, threads: int = 1) -> list[types.TextContent]:
    """
    Solve a DIMACS CNF string with CryptoMiniSat.
    """
    try:
        solver = Solver(threads=max(1, int(threads)))
        for raw in dimacs.splitlines():
            line = raw.strip()
            if not line or line.startswith("c") or line.startswith("p"):
                continue
            lits = [int(x) for x in line.split()]
            if not lits or lits[-1] != 0:
                return [types.TextContent(type="text", text=f"Invalid DIMACS line: {line}")]
            solver.add_clause(lits[:-1])

        sat, model = solver.solve()
        if sat is True:
            result = {
                "sat": True,
                "num_vars": len(model) - 1 if model else 0,
                "true_lits": [i for i in range(1, len(model)) if model[i]],
            }
            return [types.TextContent(type="text", text=str(result))]
        if sat is False:
            return [types.TextContent(type="text", text=str({"sat": False}))]
        return [types.TextContent(type="text", text=str({"sat": None, "message": "Unknown/timeout"}))]
    except Exception as exc:
        return [types.TextContent(type="text", text=f"solve_dimacs error: {type(exc).__name__}: {exc}")]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
