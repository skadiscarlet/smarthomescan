from pydantic import BaseModel, Field
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages
from typing import Annotated, List, Tuple
import operator


class Response(BaseModel):
    security_check: bool = Field(
        description="Whether there is a security check in the function."
    )
    bypass: bool = Field(
        description="Whether the security check can be bypassed. fill in false if security check does not exist."
    )


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
    tasks: list[str] | None
    past_steps: Annotated[List[Tuple], operator.add]
    func_call_results: Annotated[List[Response], operator.add]


class SubState(BaseModel):
    messages: Annotated[list, add_messages]
    curr_func_call: tuple[str, list[str]] | None
    tasks: list[str] | None
    func_call_result: Response | None
    past_steps: Annotated[List[Tuple], operator.add]


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
