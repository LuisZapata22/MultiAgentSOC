import os
import asyncio
from typing import Dict, Any
from contextlib import AsyncExitStack
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

class TelemetryAgent:
    """
    Acts as the MCP client for the Evidence Server.
    Responsible for requesting telemetry normalization.
    """
    def __init__(self):
        # Determine absolute path to the project root for module execution
        self.project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

    async def normalize(self, file_path: str, source_type: str = "zeek") -> Dict[str, Any]:
        """
        Connects to the Evidence server and calls normalize_telemetry.
        """
        server_params = StdioServerParameters(
            command="python",
            args=["-m", "src.servers.evidence.server"],
            env=dict(os.environ, PYTHONPATH=self.project_root)
        )

        async with AsyncExitStack() as stack:
            # Setup stdio transport
            read, write = await stack.enter_async_context(stdio_client(server_params))
            
            # Setup session
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()

            # Call tool
            result = await session.call_tool(
                "normalize_telemetry",
                arguments={
                    "file_path": file_path,
                    "source_type": source_type
                }
            )

            # Return a structured result for the orchestrator
            # result is a mcp.types.CallToolResult which has a content list
            # We assume the content has text
            output_text = "Unknown output"
            if result.content and len(result.content) > 0:
                output_text = result.content[0].text
                
            return {
                "status": "success" if "Successfully normalized" in output_text else "error",
                "message": output_text
            }
