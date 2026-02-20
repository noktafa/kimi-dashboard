"""LLM client with OpenAI tool calling support."""

import json
import os
import platform
import subprocess
from typing import Any, Callable, Dict, List, Optional, Type

from openai import OpenAI
from pydantic import BaseModel, Field


class ToolCall(BaseModel):
    """A tool call from the LLM."""
    id: str
    name: str
    arguments: Dict[str, Any]


class ToolResult(BaseModel):
    """Result of a tool execution."""
    tool_call_id: str
    output: str
    error: Optional[str] = None


class LLMClient:
    """OpenAI-compatible LLM client with tool calling."""
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_tokens: int = 4096
    ) -> None:
        """Initialize the LLM client.
        
        Args:
            api_key: OpenAI API key (or from OPENAI_API_KEY env var)
            base_url: API base URL for custom endpoints
            model: Model name to use
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        if not self.api_key:
            raise ValueError("API key required. Set OPENAI_API_KEY or pass api_key.")
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )
        
        self.tools: List[Dict[str, Any]] = []
        self.handlers: Dict[str, Callable[..., Any]] = {}
    
    def register_tool(
        self,
        name: str,
        handler: Callable[..., Any],
        description: str,
        parameters: Dict[str, Any]
    ) -> None:
        """Register a tool for the LLM to use.
        
        Args:
            name: Tool name
            handler: Function to call when tool is invoked
            description: Tool description for LLM
            parameters: JSON schema for tool parameters
        """
        self.tools.append({
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters
            }
        })
        self.handlers[name] = handler
    
    def register_default_tools(self) -> None:
        """Register the default sysadmin tools."""
        # run_command tool
        self.register_tool(
            name="run_command",
            handler=self._handle_run_command,
            description="Execute a shell command and return the output",
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 60)",
                        "default": 60
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Working directory for command execution",
                        "default": "."
                    }
                },
                "required": ["command"]
            }
        )
        
        # read_file tool
        self.register_tool(
            name="read_file",
            handler=self._handle_read_file,
            description="Read the contents of a file",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to read"
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of lines to read",
                        "default": 1000
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Line number to start from (1-indexed)",
                        "default": 1
                    }
                },
                "required": ["path"]
            }
        )
        
        # write_file tool
        self.register_tool(
            name="write_file",
            handler=self._handle_write_file,
            description="Write content to a file (creates or overwrites)",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to write"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file"
                    }
                },
                "required": ["path", "content"]
            }
        )
        
        # list_directory tool
        self.register_tool(
            name="list_directory",
            handler=self._handle_list_directory,
            description="List the contents of a directory",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the directory to list",
                        "default": "."
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Whether to list recursively",
                        "default": False
                    }
                }
            }
        )
        
        # get_system_info tool
        self.register_tool(
            name="get_system_info",
            handler=self._handle_get_system_info,
            description="Get system information (OS, CPU, memory, disk)",
            parameters={
                "type": "object",
                "properties": {}
            }
        )
    
    def _handle_run_command(self, command: str, timeout: int = 60, 
                           working_dir: str = ".") -> Dict[str, Any]:
        """Handle run_command tool."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "returncode": -1,
                "success": False
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "returncode": -1,
                "success": False
            }
    
    def _handle_read_file(self, path: str, limit: int = 1000, 
                         offset: int = 1) -> Dict[str, Any]:
        """Handle read_file tool."""
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
            
            start = max(0, offset - 1)
            end = min(len(lines), start + limit)
            selected_lines = lines[start:end]
            
            return {
                "content": ''.join(selected_lines),
                "total_lines": len(lines),
                "read_lines": len(selected_lines),
                "success": True
            }
        except Exception as e:
            return {
                "content": "",
                "total_lines": 0,
                "read_lines": 0,
                "success": False,
                "error": str(e)
            }
    
    def _handle_write_file(self, path: str, content: str) -> Dict[str, Any]:
        """Handle write_file tool."""
        try:
            # Create parent directories if needed
            parent = os.path.dirname(path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            
            with open(path, 'w') as f:
                f.write(content)
            
            return {
                "path": path,
                "bytes_written": len(content.encode('utf-8')),
                "success": True
            }
        except Exception as e:
            return {
                "path": path,
                "bytes_written": 0,
                "success": False,
                "error": str(e)
            }
    
    def _handle_list_directory(self, path: str = ".", 
                              recursive: bool = False) -> Dict[str, Any]:
        """Handle list_directory tool."""
        try:
            entries = []
            
            if recursive:
                for root, dirs, files in os.walk(path):
                    for d in dirs:
                        full_path = os.path.join(root, d)
                        entries.append({
                            "name": d,
                            "path": full_path,
                            "type": "directory"
                        })
                    for f in files:
                        full_path = os.path.join(root, f)
                        stat = os.stat(full_path)
                        entries.append({
                            "name": f,
                            "path": full_path,
                            "type": "file",
                            "size": stat.st_size
                        })
            else:
                for entry in os.listdir(path):
                    full_path = os.path.join(path, entry)
                    is_dir = os.path.isdir(full_path)
                    entry_info = {
                        "name": entry,
                        "path": full_path,
                        "type": "directory" if is_dir else "file"
                    }
                    if not is_dir:
                        entry_info["size"] = os.path.getsize(full_path)
                    entries.append(entry_info)
            
            return {
                "path": path,
                "entries": entries,
                "count": len(entries),
                "success": True
            }
        except Exception as e:
            return {
                "path": path,
                "entries": [],
                "count": 0,
                "success": False,
                "error": str(e)
            }
    
    def _handle_get_system_info(self) -> Dict[str, Any]:
        """Handle get_system_info tool."""
        info = {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "hostname": platform.node(),
            "success": True
        }
        
        # Try to get memory info
        try:
            import psutil
            mem = psutil.virtual_memory()
            info["memory"] = {
                "total": mem.total,
                "available": mem.available,
                "percent": mem.percent
            }
            disk = psutil.disk_usage('/')
            info["disk"] = {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            }
            cpu_percent = psutil.cpu_percent(interval=1)
            info["cpu_percent"] = cpu_percent
        except ImportError:
            info["memory"] = "psutil not installed"
            info["disk"] = "psutil not installed"
        
        return info
    
    def chat(
        self,
        messages: List[Dict[str, str]],
        execute_tools: bool = True,
        max_tool_iterations: int = 10
    ) -> str:
        """Send a chat message and handle tool calls.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            execute_tools: Whether to execute tool calls
            max_tool_iterations: Maximum tool call iterations
            
        Returns:
            Final response content
        """
        current_messages = messages.copy()
        iterations = 0
        
        while iterations < max_tool_iterations:
            iterations += 1
            
            # Make API call
            kwargs: Dict[str, Any] = {
                "model": self.model,
                "messages": current_messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens
            }
            
            if self.tools:
                kwargs["tools"] = self.tools
                kwargs["tool_choice"] = "auto"
            
            response = self.client.chat.completions.create(**kwargs)
            message = response.choices[0].message
            
            # Check for tool calls
            if not message.tool_calls or not execute_tools:
                return message.content or ""
            
            # Add assistant message to conversation
            current_messages.append({
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments
                        }
                    }
                    for tc in message.tool_calls
                ]
            })
            
            # Execute tool calls
            for tool_call in message.tool_calls:
                name = tool_call.function.name
                arguments = json.loads(tool_call.function.arguments)
                
                if name in self.handlers:
                    try:
                        result = self.handlers[name](**arguments)
                        tool_result = json.dumps(result)
                    except Exception as e:
                        tool_result = json.dumps({
                            "success": False,
                            "error": str(e)
                        })
                else:
                    tool_result = json.dumps({
                        "success": False,
                        "error": f"Unknown tool: {name}"
                    })
                
                current_messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": tool_result
                })
        
        return "Maximum tool iterations reached"
