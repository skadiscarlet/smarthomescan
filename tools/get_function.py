from my_types import FuncCallNode, FuncArg
from pydantic import BaseModel, Field
from typing import Type
from langchain.tools import BaseTool
from utils import get_func


class GetFuncInput(BaseModel):
    full_path: str = Field(
        description="full class.method path like com.xxx.xxx.ClassName#MethodName"
    )


class GetFuncTool(BaseTool):
    target: str = ""
    name: str = "get_func"
    description: str = (
        "if you think you need more functions' information. you can use this tool to get full content of a function by its full path like com.xxx.xxx.ClassName#MethodName"
    )
    args_schema: Type[BaseModel] = GetFuncInput

    def _run(self, full_path: str, run_manager=None) -> str:
        """Use the tool."""
        return get_func(full_path, self.target)

    async def _arun(self, query: str, run_manager=None) -> str:
        """Use the tool asynchronously."""
        raise NotImplementedError("Calculator does not support async")
