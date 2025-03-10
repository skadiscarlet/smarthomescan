from pydantic import BaseModel
from typing import Annotated
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages


class State(TypedDict):
    messages: Annotated[list, add_messages]
    reachable: bool
    flow: str
    function_content: str
    source_arg: str
    sink_call: str
    next_node: str | None
    last_node: str | None
    func_call_dict: dict
    curr_func_call: tuple[str, list[str]] | None


class FuncArg(BaseModel):
    arg_name: str
    arg_type: str


class FuncCallNode(BaseModel):
    func_name: str
    func_args: list[FuncArg]
    func_ret_type: str
    func_content: str


class LLMError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class UnknownError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
