"""IDA startup script — auto-starts MCP RPC server."""
import idaapi
import ida_auto

def on_analysis_done():
    """Called after auto-analysis completes."""
    try:
        idaapi.load_and_run_plugin("ida_mcp", 0)
        print("[ida_auto] MCP plugin activated successfully")
    except Exception as e:
        print(f"[ida_auto] MCP activation failed: {e}")

# Register callback for when auto-analysis completes
class AnalysisDoneHook(ida_auto.auto_empty_queue_t):
    def run(self):
        on_analysis_done()
        return False

ida_auto.register_post_event(AnalysisDoneHook())
