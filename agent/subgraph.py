import json
from config import api_key, base_url, api_key1, base_url1
import os
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import ToolMessage, AIMessage, HumanMessage
from langchain_deepseek import ChatDeepSeek
from langchain_openai import ChatOpenAI
from tools.get_function import GetFuncTool
from agent.prompts import (
    CTF_OUT,
    template4CTF,
    CB1_OUT,
    template4CB1,
    CB2_OUT,
    template4CB2,
)
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import PromptTemplate, StringPromptTemplate
from my_types import State

# os.environ["OPENAI_API_KEY"] = api_key
# os.environ["DEEPSEEK_API_KEY"] = api_key
# os.environ["DEEPSEEK_API_BASE"] = base_url
# agent1 = ChatOpenAI(api_key=api_key1, model="gpt-4o", base_url=base_url1)
agent1 = ChatOpenAI(api_key=api_key, model="qwen-plus", base_url=base_url)
# agent2 = ChatDeepSeek(model="deepseek-v3")
agent2 = ChatOpenAI(api_key=api_key, model="qwen-plus", base_url=base_url)
agent3 = ChatOpenAI(api_key=api_key, model="qwen-max", base_url=base_url)

graph_builder = StateGraph(State)
tool = GetFuncTool(target="mihome")
tools = [tool]
agent1 = agent1.bind_tools(tools)
agent3 = agent3.bind_tools(tools)


def CheckTaintFlow(state: State):
    parser = PydanticOutputParser(pydantic_object=CTF_OUT)
    prompt = PromptTemplate(
        template=template4CTF,
        input_variables=["function_content", "source_arg", "sink_call"],
        partial_variables={"format_instructions": parser.get_format_instructions()},
    ).format(
        function_content=state["function_content"],
        source_arg=state["source_arg"],
        sink_call=state["sink_call"],
    )
    messages = [HumanMessage(content=prompt)]
    response = agent2.invoke(messages)
    output = parser.parse(response.content)
    return {
        "messages": messages + [response],
        "reachable": output.reachable,
        "flow": output.flow,
        "last_node": "CTF",
        "from_tool": False,
    }


def CheckBranch(state: State):
    if state.get("last_node") == "CTF":
        parser = PydanticOutputParser(pydantic_object=CB1_OUT)
        prompt = PromptTemplate(
            template=template4CB1,
            input_variables=[
                "function_content",
                "source_arg",
                "sink_call",
                "tainted_flow",
            ],
            partial_variables={"format_instructions": parser.get_format_instructions()},
        ).format(
            function_content=state["function_content"],
            source_arg=state["source_arg"],
            sink_call=state["sink_call"],
            tainted_flow=state["flow"],
        )
        messages = [HumanMessage(content=prompt)]
        response = agent3.invoke(messages)
        output = parser.parse(response.content)
        return {
            "messages": messages + [response],
            "CB_flag": "continue" if output.need_check else "end",
            "CB_tasks": output.tasks,
            "last_node": "CB",
            "from_tool": False,
        }
    elif state.get("last_node") == "subCB":
        parser = PydanticOutputParser(pydantic_object=CB2_OUT)
        messages = state["messages"]
        prompt = PromptTemplate(
            template=template4CB2,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        ).format()
        messages.append(HumanMessage(content=prompt))
        response = agent2.invoke(messages)
        output = parser.parse(response.content)
        return {
            "messages": messages + [response],
            "CB_flag": "end",
            "reachable": output.reachable,
            "last_node": "CB",
            "from_tool": False,
        }


def subCheckBranch(state: State):
    if state.get("from_tool"):
        messages = state["messages"]
        messages.append(HumanMessage(content="Now, continue to current Task"))
        response = agent1.invoke(messages)

        return {
            "messages": messages + [response],
            "subCB_flag": True if len(state["CB_tasks"]) > 0 else False,
            "last_node": "subCB",
            "from_tool": False,
        }
    else:
        task = state["CB_tasks"].pop(0)
        messages = state["messages"]
        messages.append(HumanMessage(content=task))
        response = agent1.invoke(messages)
        return {
            "messages": messages + [response],
            "subCB_flag": True if len(state["CB_tasks"]) > 0 else False,
            "last_node": "subCB",
            "from_tool": False,
        }


# TODO
def CheckFilter(state: State):
    return {"messages": state["messages"]}


# TODO
def subCheckFilter(state: State):
    return {"messages": state["messages"]}


class ToolNode:
    def __init__(self, tools: list) -> None:
        self.tools_by_name = {tool.name: tool for tool in tools}

    def __call__(self, inputs: dict):
        if messages := inputs.get("messages", []):
            message = messages[-1]
        else:
            raise ValueError("No message found in input")
        outputs = []
        for tool_call in message.tool_calls:
            tool_result = self.tools_by_name[tool_call["name"]].invoke(
                tool_call["args"]
            )
            outputs.append(
                ToolMessage(
                    content=json.dumps(tool_result),
                    name=tool_call["name"],
                    tool_call_id=tool_call["id"],
                )
            )
        return {
            "messages": outputs,
            "subCB_flag": True,
            "subCF_flag": True,
            "from_tool": True,
        }


tool_node = ToolNode(tools=[tool])
graph_builder.add_node("Tools", tool_node)
graph_builder.add_node("CTF", CheckTaintFlow)
graph_builder.add_node("CB", CheckBranch)
graph_builder.add_node("subCB", subCheckBranch)
graph_builder.add_node("CF", CheckFilter)
graph_builder.add_node("subCF", subCheckFilter)


def route_CTF2CB(
    state: State,
):
    if not state.get("reachable"):
        return END
    else:
        return "CB"


def route_CB2CF(
    state: State,
):
    if not state.get("reachable"):
        return END
    if state.get("CB_flag") == "end":
        return "CF"
    if len(state["CB_tasks"]) != 0:
        return "subCB"


# TODO: 目前的代码本质上是要ai自行确定审查方式
# 后需要加入更精确和复杂的prompt引导
def route_subCB(
    state: State,
):
    if messages := state.get("messages", []):
        ai_message = messages[-1]
    else:
        raise ValueError(f"No messages found in input state to tool_edge: {state}")
    if hasattr(ai_message, "tool_calls") and len(ai_message.tool_calls) > 0:
        return "Tools"

    if state["subCB_flag"] == True:
        return "subCB"
    else:
        return "CB"


def route_tools(
    state: State,
):
    if state.get("last_node"):
        return state.get("last_node")
    else:
        return END


graph_builder.add_edge(START, "CTF")
graph_builder.add_conditional_edges("CTF", route_CTF2CB, {"CB": "CB", END: END})
graph_builder.add_conditional_edges(
    "CB", route_CB2CF, {"CF": END, "subCB": "subCB", END: END}
)  # test for CB
graph_builder.add_conditional_edges(
    "subCB", route_subCB, {"CB": "CB", "subCB": "subCB", "Tools": "Tools"}
)
graph_builder.add_conditional_edges(
    "Tools", route_tools, {"subCB": "subCB", "subCF": "subCF"}
)
graph_builder.add_edge("CF", END)

graph = graph_builder.compile()


# def stream_graph_updates(user_input: str):
#     for event in graph.stream({"messages": [("user", user_input)]}):
#         for value in event.values():
#             print("Assistant:", value["messages"][-1].content)

if __name__ == "__main__":
    from IPython.display import Image, display

    try:
        display(Image(graph.get_graph().draw_mermaid_png()))
    except Exception:
        pass
