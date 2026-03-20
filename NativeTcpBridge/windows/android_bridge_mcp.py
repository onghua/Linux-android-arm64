#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from html import escape
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

PROJECT_WINDOWS_DIR = Path(__file__).resolve().parents[1] / "windows"
if str(PROJECT_WINDOWS_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_WINDOWS_DIR))

from tcp_server import (  # noqa: E402
    AndroidBridgeClient,
    DEFAULT_ANDROID_HOST,
    DEFAULT_ANDROID_PORT,
    DEFAULT_ANDROID_TIMEOUT_SECONDS,
)

DEFAULT_MCP_BIND_HOST = os.getenv("ANDROID_MCP_BIND_HOST", "127.0.0.1").strip() or "127.0.0.1"
DEFAULT_MCP_BIND_PORT = int(os.getenv("ANDROID_MCP_BIND_PORT", "13337"))
DEFAULT_MCP_PATH = os.getenv("ANDROID_MCP_PATH", "/mcp")
DEFAULT_MCP_CONFIG_PATH = os.getenv("ANDROID_MCP_CONFIG_PATH", "/config.html")

bridge = AndroidBridgeClient(
    host=DEFAULT_ANDROID_HOST,
    port=DEFAULT_ANDROID_PORT,
    timeout_seconds=DEFAULT_ANDROID_TIMEOUT_SECONDS,
)
mcp = FastMCP(
    "NativeTcpBridge Android MCP",
    host=DEFAULT_MCP_BIND_HOST,
    port=DEFAULT_MCP_BIND_PORT,
    streamable_http_path=DEFAULT_MCP_PATH,
)


@mcp.resource("android://connection")
def android_connection() -> dict[str, Any]:
    """Return the current Android TCP connection settings used by this MCP server."""
    return bridge.current_config()


@mcp.resource("android://protocol")
def android_protocol() -> dict[str, Any]:
    """Return the structured bridge protocol description exposed by the Android tcp_server."""
    return bridge.describe()


@mcp.tool()
def configure_android_bridge(
    host: str = DEFAULT_ANDROID_HOST,
    timeout_seconds: float = DEFAULT_ANDROID_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Configure the Android tcp_server target. Use host='auto' to scan the LAN for a reachable device."""
    return bridge.configure(host=host, timeout_seconds=timeout_seconds)


@mcp.tool()
def discover_android_bridges() -> dict[str, Any]:
    """Discover Android tcp_server candidates on the LAN and show the current TCP bridge state."""
    return bridge.discover()


@mcp.tool()
def android_bridge_ping() -> dict[str, Any]:
    """Check whether the currently configured Android tcp_server is reachable."""
    return bridge.ping()


@mcp.tool()
def android_target_set_pid(pid: int) -> dict[str, Any]:
    """Bind all scan, viewer, and breakpoint operations to a known PID."""
    return bridge.target_set_pid(pid)


@mcp.tool()
def android_target_attach_package(package_name: str) -> dict[str, Any]:
    """Resolve a package name to PID and make that process the current target."""
    return bridge.target_attach_package(package_name)


@mcp.tool()
def android_target_current() -> dict[str, Any]:
    """Read the current target process bound inside the Android tcp_server."""
    return bridge.target_current()


@mcp.tool()
def android_memory_regions() -> dict[str, Any]:
    """Fetch the full module and memory region map for the current target process."""
    return bridge.memory_regions()


@mcp.tool()
def android_module_address(module_name: str, segment_index: int = 0, which: str = "start") -> dict[str, Any]:
    """Resolve a module segment start or end address from the current target process."""
    which_token = which.strip().lower()
    if which_token not in {"start", "end"}:
        raise ValueError("which must be 'start' or 'end'")
    return bridge.module_address(module_name, segment_index, which_token)


@mcp.tool()
def android_memory_scan_start(
    value_type: str,
    mode: str,
    value: str = "",
    range_max: str = "",
) -> dict[str, Any]:
    """Start a new memory scan. Example: value_type='i32', mode='eq', value='1234'."""
    type_token = value_type.strip().lower()
    mode_token = mode.strip().lower()
    if mode_token != "unknown" and not str(value).strip():
        raise ValueError("value is required unless mode is 'unknown'")
    return bridge.memory_scan_start(type_token, mode_token, value, range_max)


@mcp.tool()
def android_memory_scan_refine(
    value_type: str,
    mode: str,
    value: str = "",
    range_max: str = "",
) -> dict[str, Any]:
    """Refine the current memory scan result set."""
    type_token = value_type.strip().lower()
    mode_token = mode.strip().lower()
    if mode_token != "unknown" and not str(value).strip():
        raise ValueError("value is required unless mode is 'unknown'")
    return bridge.memory_scan_refine(type_token, mode_token, value, range_max)


@mcp.tool()
def android_memory_scan_results(start: int = 0, count: int = 100, value_type: str = "i32") -> dict[str, Any]:
    """Read one page of the current memory scan results."""
    if count <= 0 or count > 2000:
        raise ValueError("count must be in 1..2000")
    return bridge.memory_scan_results(start, count, value_type)


@mcp.tool()
def android_memory_view_open(address: int | str, view_format: str = "hex") -> dict[str, Any]:
    """Open the memory viewer at an address. Use view_format='disasm' to request disassembly instead of raw hex bytes."""
    return bridge.memory_view_open(address, view_format)


@mcp.tool()
def android_memory_view_move(lines: int, step: int | None = None) -> dict[str, Any]:
    """Move the current memory viewer window by lines."""
    return bridge.memory_view_move(lines, step)


@mcp.tool()
def android_memory_view_offset(offset: str) -> dict[str, Any]:
    """Move the current viewer base by an offset such as '+0x20' or '-0x10'."""
    return bridge.memory_view_offset(offset)


@mcp.tool()
def android_memory_view_set_format(view_format: str) -> dict[str, Any]:
    """Change the current viewer format. Use 'disasm' for disassembly, otherwise the viewer returns formatted memory values."""
    return bridge.memory_view_set_format(view_format)


@mcp.tool()
def android_memory_view_read() -> dict[str, Any]:
    """Read the current viewer snapshot. In disasm mode, the result is in data.disasm; in other modes, raw bytes remain in data.data_hex."""
    return bridge.memory_view_read()


@mcp.tool()
def android_breakpoint_list() -> dict[str, Any]:
    """List the current hardware breakpoint state and saved breakpoint records."""
    return bridge.breakpoint_list()


@mcp.tool()
def android_breakpoint_set(address: int | str, bp_type: int, bp_scope: int, length: int) -> dict[str, Any]:
    """Create a hardware breakpoint on the current target process."""
    return bridge.breakpoint_set(address, bp_type, bp_scope, length)


@mcp.tool()
def android_breakpoint_clear_all() -> dict[str, Any]:
    """Remove all active hardware breakpoints from the current target process."""
    return bridge.breakpoint_clear_all()


@mcp.tool()
def android_breakpoint_record_remove(index: int) -> dict[str, Any]:
    """Remove one saved hardware breakpoint record by index."""
    return bridge.breakpoint_record_remove(index)


@mcp.tool()
def android_breakpoint_record_update(index: int, field: str, value: int | str) -> dict[str, Any]:
    """Patch one field inside a saved hardware breakpoint record."""
    return bridge.breakpoint_record_update(index, field, value)


def _normalize_http_path(path: str) -> str:
    normalized = str(path).strip() or "/mcp"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if len(normalized) > 1:
        normalized = normalized.rstrip("/")
    return normalized or "/mcp"


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Expose the NativeTcpBridge Android bridge as an MCP server.",
    )
    parser.add_argument(
        "--mcp-host",
        default=DEFAULT_MCP_BIND_HOST,
        help="Bind host for the local MCP web server.",
    )
    parser.add_argument(
        "--mcp-port",
        type=int,
        default=DEFAULT_MCP_BIND_PORT,
        help="Bind port for the local MCP web server.",
    )
    parser.add_argument(
        "--mcp-path",
        default=DEFAULT_MCP_PATH,
        help="HTTP endpoint path for streamable-http clients.",
    )
    parser.add_argument(
        "--mcp-config-path",
        default=DEFAULT_MCP_CONFIG_PATH,
        help="Config page path for the local browser UI.",
    )
    parser.add_argument(
        "--android-host",
        default=DEFAULT_ANDROID_HOST,
        help=f"Target Android tcp_server host. Default is 'auto'; the Android port defaults to {DEFAULT_ANDROID_PORT}.",
    )
    parser.add_argument(
        "--android-timeout",
        type=float,
        default=DEFAULT_ANDROID_TIMEOUT_SECONDS,
        help="Timeout in seconds for Android tcp_server requests.",
    )
    return parser


def _format_http_endpoint(host: str, port: int, path: str) -> str:
    display_host = "127.0.0.1" if host == "0.0.0.0" else host
    return f"http://{display_host}:{port}{path}"


TOOL_META: dict[str, tuple[str, str, str]] = {
    "configure_android_bridge": ("Bridge Setup", "Set or update the Android tcp_server host.", '{"host":"auto","timeout_seconds":8}'),
    "discover_android_bridges": ("Bridge Setup", "Scan the LAN for Android tcp_server candidates when the host is unknown.", "{}"),
    "android_bridge_ping": ("Bridge Setup", "Check whether the current Android TCP target is reachable.", "{}"),
    "android_target_set_pid": ("Target Selection", "Bind the bridge to a known PID before scanning, viewing, or breakpoints.", '{"pid":1234}'),
    "android_target_attach_package": ("Target Selection", "Resolve a package name to PID and make it the current target process.", '{"package_name":"com.example.app"}'),
    "android_target_current": ("Target Selection", "Read the currently bound PID.", "{}"),
    "android_memory_regions": ("Target Selection", "Fetch the full memory map so you can enumerate module base addresses.", "{}"),
    "android_module_address": ("Target Selection", "Resolve a specific module segment start or end address directly.", '{"module_name":"libgame.so","segment_index":0,"which":"start"}'),
    "android_memory_scan_start": ("Memory Scan", "Start a fresh memory scan.", '{"value_type":"i32","mode":"eq","value":"1234"}'),
    "android_memory_scan_refine": ("Memory Scan", "Narrow an existing memory scan result set.", '{"value_type":"i32","mode":"eq","value":"1234"}'),
    "android_memory_scan_results": ("Memory Scan", "Page through scan hits after a first/next scan.", '{"start":0,"count":100,"value_type":"i32"}'),
    "android_memory_view_open": ("Memory View", "Open the memory viewer at an address. For assembly, set view_format to disasm.", '{"address":"0x12345678","view_format":"disasm"}'),
    "android_memory_view_move": ("Memory View", "Move the current viewer window.", '{"lines":16}'),
    "android_memory_view_offset": ("Memory View", "Move the current viewer base by a relative offset.", '{"offset":"+0x20"}'),
    "android_memory_view_set_format": ("Memory View", "Switch the viewer between hex, integer, float, and disassembly formats.", '{"view_format":"disasm"}'),
    "android_memory_view_read": ("Memory View", "Read the current viewer snapshot. In disasm mode, use data.disasm instead of data.data_hex.", "{}"),
    "android_breakpoint_list": ("Breakpoints", "Inspect current hardware breakpoint state.", "{}"),
    "android_breakpoint_set": ("Breakpoints", "Create a hardware breakpoint on the current target.", '{"address":"0x12345678","bp_type":1,"bp_scope":0,"length":4}'),
    "android_breakpoint_clear_all": ("Breakpoints", "Remove all active hardware breakpoints.", "{}"),
    "android_breakpoint_record_remove": ("Breakpoints", "Delete one saved hardware breakpoint record.", '{"index":0}'),
    "android_breakpoint_record_update": ("Breakpoints", "Patch one field inside a saved hardware breakpoint record.", '{"index":0,"field":"addr","value":"0x12345678"}'),
}


def _format_tool_parameters(parameters: dict[str, Any] | None) -> str:
    if not parameters:
        return "none"

    properties = parameters.get("properties", {})
    required = set(parameters.get("required", []))
    parts: list[str] = []
    for name, schema in properties.items():
        type_name = schema.get("type", "any")
        fragment = f"{name}: {type_name}"
        if name not in required:
            if "default" in schema:
                fragment += f" = {schema['default']!r}"
            else:
                fragment += " (optional)"
        parts.append(fragment)
    return ", ".join(parts) if parts else "none"


def _build_tool_catalog() -> list[dict[str, str]]:
    return [
        {
            "name": tool.name,
            "description": tool.description or "",
            "when": TOOL_META.get(tool.name, ("Bridge Setup", "Use this tool according to its description.", "{}"))[1],
            "parameters": _format_tool_parameters(tool.parameters),
            "example": TOOL_META.get(tool.name, ("Bridge Setup", "", "{}"))[2],
        }
        for tool in mcp._tool_manager.list_tools()
    ]


def _group_tool_catalog(tool_catalog: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    by_group: dict[str, list[dict[str, str]]] = {}
    for tool in tool_catalog:
        group = TOOL_META.get(tool["name"], ("Bridge Setup", "", ""))[0]
        by_group.setdefault(group, []).append(tool)
    return by_group


def _render_tool_guide(tool_catalog: list[dict[str, str]]) -> str:
    sections: list[str] = []
    for group_name, items in _group_tool_catalog(tool_catalog).items():
        sections.append(group_name)
        for tool in items:
            sections.extend(
                [
                    f"- {tool['name']}",
                    f"  Purpose: {tool['description']}",
                    f"  Use when: {tool['when']}",
                    f"  Parameters: {tool['parameters']}",
                    f"  Example args: {tool['example']}",
                ]
            )
        sections.append("")
    return "\n".join(sections).strip()


def _build_connection_steps(runtime: dict[str, Any]) -> str:
    return "\n".join(
        [
            "1. Connect to this MCP server using Streamable HTTP.",
            f"2. Use this URL: {runtime['streamable_http_url']}",
            "3. Initialize MCP, call tools/list, then call tools by their exact names.",
            "4. Start with configure_android_bridge, android_bridge_ping, and android_target_attach_package.",
            "5. For module base addresses use android_memory_regions or android_module_address.",
            "6. For disassembly use android_memory_view_open(view_format='disasm') and then read data.disasm from android_memory_view_read.",
            "7. The Android bridge also exposes a structured operation protocol at android://protocol.",
        ]
    )


def _build_curl_example(runtime: dict[str, Any]) -> str:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "curl-client", "version": "1.0"},
        },
    }
    return (
        "curl -X POST "
        f"\"{runtime['streamable_http_url']}\" "
        "-H \"Content-Type: application/json\" "
        "-H \"Accept: application/json, text/event-stream\" "
        f"-d '{json.dumps(body, ensure_ascii=False)}'"
    )


def _build_python_example(runtime: dict[str, Any]) -> str:
    return "\n".join(
        [
            "import requests",
            f"url = {runtime['streamable_http_url']!r}",
            "payload = {",
            "    'jsonrpc': '2.0',",
            "    'id': 1,",
            "    'method': 'initialize',",
            "    'params': {",
            "        'protocolVersion': '2025-03-26',",
            "        'capabilities': {},",
            "        'clientInfo': {'name': 'python-client', 'version': '1.0'},",
            "    },",
            "}",
            "resp = requests.post(url, json=payload, headers={'Accept': 'application/json, text/event-stream'})",
            "print(resp.status_code)",
            "print(resp.text)",
            "# Then call tools/list, then tools/call.",
        ]
    )


def _build_startup_handoff(runtime: dict[str, Any]) -> str:
    return "\n".join(
        [
            "[MCP] AI connection guide:",
            *[f"  {line}" for line in _build_connection_steps(runtime).splitlines()],
            "[MCP] curl initialize example:",
            f"  {_build_curl_example(runtime)}",
            "[MCP] python initialize example:",
            *[f"  {line}" for line in _build_python_example(runtime).splitlines()],
        ]
    )


def _build_config_html(runtime: dict[str, Any]) -> str:
    tool_catalog = _build_tool_catalog()
    try:
        protocol_text = json.dumps(bridge.describe(), ensure_ascii=False, indent=2)
    except Exception as exc:  # noqa: BLE001
        protocol_text = f"unavailable: {exc}"

    guide_text = "\n\n".join(
        [
            "NativeTcpBridge MCP",
            f"MCP URL\n{runtime['streamable_http_url']}",
            f"Connection Steps\n{_build_connection_steps(runtime)}",
            f"curl Initialize Example\n{_build_curl_example(runtime)}",
            f"Python Initialize Example\n{_build_python_example(runtime)}",
            f"Bridge Protocol\n{protocol_text}",
            f"Tools\n{_render_tool_guide(tool_catalog)}",
        ]
    )

    return "\n".join(
        [
            "<!doctype html>",
            "<html lang='en'>",
            "<head>",
            "  <meta charset='utf-8'>",
            "  <meta name='viewport' content='width=device-width, initial-scale=1'>",
            "  <title>NativeTcpBridge MCP Config</title>",
            "  <style>body{margin:0;padding:24px;font:14px/1.6 Consolas,'Courier New',monospace;background:#faf8f2;color:#1f2328}pre{white-space:pre-wrap;word-break:break-word}</style>",
            "</head>",
            "<body>",
            f"  <pre>{escape(guide_text)}</pre>",
            "</body>",
            "</html>",
        ]
    )


def _run_http_suite(runtime: dict[str, Any]) -> None:
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import HTMLResponse, RedirectResponse
    from starlette.routing import Route

    streamable_app = mcp.streamable_http_app()

    async def config_page(_) -> HTMLResponse:
        return HTMLResponse(_build_config_html(runtime))

    async def root_page(_) -> RedirectResponse:
        return RedirectResponse(url=runtime["config_path"], status_code=307)

    middleware = list(streamable_app.user_middleware)
    routes = list(streamable_app.routes)
    routes.append(Route(runtime["config_path"], endpoint=config_page, methods=["GET"]))
    routes.append(Route("/", endpoint=root_page, methods=["GET"]))

    app = Starlette(
        debug=mcp.settings.debug,
        routes=routes,
        middleware=middleware,
        lifespan=streamable_app.router.lifespan_context,
    )

    config = uvicorn.Config(
        app,
        host=mcp.settings.host,
        port=mcp.settings.port,
        log_level=mcp.settings.log_level.lower(),
    )
    server = uvicorn.Server(config)
    server.run()


def _emit_startup_info(runtime: dict[str, Any]) -> None:
    print("[MCP] Server started:", file=sys.stderr, flush=True)
    print(f"  Streamable HTTP: {runtime['streamable_http_url']}", file=sys.stderr, flush=True)
    print(f"  Config: {runtime['config_url']}", file=sys.stderr, flush=True)
    print(_build_startup_handoff(runtime), file=sys.stderr, flush=True)


def _configure_runtime(args: argparse.Namespace) -> dict[str, Any]:
    bridge.configure(
        host=args.android_host,
        timeout_seconds=args.android_timeout,
    )

    mcp.settings.host = args.mcp_host.strip() or DEFAULT_MCP_BIND_HOST
    mcp.settings.port = int(args.mcp_port)
    mcp.settings.streamable_http_path = _normalize_http_path(args.mcp_path)
    config_path = _normalize_http_path(args.mcp_config_path)

    runtime: dict[str, Any] = {
        "config_path": config_path,
        "streamable_http_url": _format_http_endpoint(
            mcp.settings.host,
            mcp.settings.port,
            mcp.settings.streamable_http_path,
        ),
        "config_url": _format_http_endpoint(
            mcp.settings.host,
            mcp.settings.port,
            config_path,
        ),
    }
    return runtime


def main() -> int:
    parser = _build_arg_parser()
    args = parser.parse_args()
    runtime = _configure_runtime(args)
    _emit_startup_info(runtime)
    _run_http_suite(runtime)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
