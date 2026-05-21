# Copyright © 2025–2026 Stefano Noferi & Admina contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Mock MCP Server — Simulates real MCP tool endpoints for testing Admina.
Implements JSON-RPC 2.0 over HTTP (Streamable HTTP transport).
"""

import json
import logging
import random
from datetime import UTC, datetime

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MockMCP] %(message)s")
logger = logging.getLogger("mock-mcp")

_VERSION = "1.0.0"
try:
    from admina import __version__ as _VERSION  # noqa: F811
except ImportError:
    pass  # standalone mode (Docker)

app = FastAPI(title="Mock MCP Server", version=_VERSION)

# ── Registered Tools ─────────────────────────────────────────
TOOLS = {
    "get_stock_price": {
        "description": "Get current stock price for a ticker symbol",
        "inputSchema": {
            "type": "object",
            "properties": {"ticker": {"type": "string"}},
            "required": ["ticker"],
        },
    },
    "execute_trade": {
        "description": "Execute a stock trade",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticker": {"type": "string"},
                "action": {"type": "string", "enum": ["buy", "sell"]},
                "quantity": {"type": "integer"},
            },
            "required": ["ticker", "action", "quantity"],
        },
    },
    "query_patient_records": {
        "description": "Query patient medical records",
        "inputSchema": {
            "type": "object",
            "properties": {"patient_id": {"type": "string"}},
            "required": ["patient_id"],
        },
    },
    "send_email": {
        "description": "Send an email",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    "read_file": {
        "description": "Read a file from the filesystem",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
}


@app.post("/mcp")
@app.post("/mcp/{path:path}")
async def handle_mcp(request: Request, path: str = ""):
    """Handle MCP JSON-RPC requests."""
    body = await request.json()
    method = body.get("method", "")
    params = body.get("params", {})
    req_id = body.get("id")

    logger.info(f"📨 Received: method={method}, params={json.dumps(params)[:200]}")

    if method == "initialize":
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "mock-mcp-server", "version": _VERSION},
                },
            }
        )

    elif method == "tools/list":
        tools_list = [
            {"name": name, "description": t["description"], "inputSchema": t["inputSchema"]}
            for name, t in TOOLS.items()
        ]
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools_list},
            }
        )

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        result = _execute_tool(tool_name, arguments)
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
            }
        )

    else:
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"message": f"Method '{method}' handled (mock)"},
            }
        )


def _execute_tool(name: str, args: dict) -> dict:
    """Simulate tool execution with realistic responses."""

    if name == "get_stock_price":
        ticker = args.get("ticker", "AAPL")
        price = round(random.uniform(50, 500), 2)
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "ticker": ticker,
                            "price": price,
                            "currency": "USD",
                            "timestamp": datetime.now(UTC).isoformat(),
                        }
                    ),
                }
            ],
        }

    elif name == "execute_trade":
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "order_id": f"ORD-{random.randint(10000, 99999)}",
                            "status": "executed",
                            "ticker": args.get("ticker"),
                            "action": args.get("action"),
                            "quantity": args.get("quantity"),
                            "fill_price": round(random.uniform(50, 500), 2),
                            "timestamp": datetime.now(UTC).isoformat(),
                        }
                    ),
                }
            ],
        }

    elif name == "query_patient_records":
        # Returns PII to test redaction
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "patient_id": args.get("patient_id"),
                            "name": "John Smith",
                            "email": "john.smith@example.com",
                            "phone": "+1-555-123-4567",
                            "ssn": "123-45-6789",
                            "diagnosis": "Type 2 Diabetes",
                            "medications": ["Metformin 500mg", "Lisinopril 10mg"],
                        }
                    ),
                }
            ],
        }

    elif name == "send_email":
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "status": "sent",
                            "message_id": f"MSG-{random.randint(10000, 99999)}",
                            "to": args.get("to"),
                            "subject": args.get("subject"),
                        }
                    ),
                }
            ],
        }

    elif name == "read_file":
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Contents of {args.get('path', 'file')}: [mock file content]",
                }
            ],
        }

    return {
        "content": [{"type": "text", "text": f"Tool '{name}' executed (mock)"}],
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "mock-mcp-server"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9000)
