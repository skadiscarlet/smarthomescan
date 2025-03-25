import json
from config import api_key, base_url, api_key1, base_url1
from utils import get_func
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import ToolMessage, AIMessage, HumanMessage
from langchain_openai import ChatOpenAI
from tools.get_function import GetFuncTool
from langgraph.prebuilt import create_react_agent, ToolNode
from agent.prompts import (
    CTF_OUT,
    template4CTF,
    CB1_OUT,
    template4CB1,
    CB2_OUT,
    template4CB2,
    CB3_OUT,
    template4CB3,
    subCB1_OUT,
    template4subCB1,
    subCB2_OUT,
    template4subCB2,
)
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import PromptTemplate, StringPromptTemplate
from my_types import State, Response
from agent.subgraph_CB import subgraph as subgraph_CB

llm1 = ChatOpenAI(api_key=api_key1, model="gpt-4o-2024-08-06", base_url=base_url1)
llm2 = ChatOpenAI(api_key=api_key1, model="o3-mini", base_url=base_url1)


tool = GetFuncTool(target="mihome")
tools = [tool]
analyzer = llm1
planner = llm2.bind_tools(tools)


def CheckTaintFlow(state: State):
    prompt = template4CTF.format(
        function_content=state["function_content"],
        source_arg=state["source_arg"],
        sink_call=state["sink_call"],
    )
    messages = [HumanMessage(content=prompt)]
    output = analyzer.with_structured_output(CTF_OUT, strict=True).invoke(messages)
    print(output)
    return {
        # "messages": messages + [output],
        "reachable": output.reachable,
        "flow": output.flow,
        "next_node": "CB" if output.reachable else END,
        "last_node": "CTF",
    }


def CheckBranch(state: State):
    if state.get("last_node") == "CTF":
        prompt = template4CB1.format(
            function_content=state["function_content"],
            source_arg=state["source_arg"],
            sink_call=state["sink_call"],
            tainted_flow=state["flow"],
        )
        messages = [HumanMessage(content=prompt)]
        output = analyzer.with_structured_output(CB1_OUT).invoke(messages)
        if not output.need_check:
            return {
                "next_node": "CF",
                "last_node": "CB",
            }

        else:
            prompt = template4CB2.format()
            messages = [HumanMessage(content=prompt)]
            output = planner.with_structured_output(CB2_OUT).invoke(messages)
            return {
                "next_node": "CB",
                "func_call_dict": output.func_call_dict,
                "last_node": "CB",
            }

    if len(state.get("func_call_dict")) <= 0:
        prompt = template4CB3.format()
        messages = [HumanMessage(content=prompt)]
        output = analyzer.with_structured_output(CB3_OUT).invoke(messages)

        return {
            "reachable": output.reachable,
            "next_node": "CF" if output.reachable else END,
            "last_node": "CB",
        }
    else:
        func_call, args = state["func_call_dict"].popitem()
        output = subgraph_CB.invoke(
            {
                "messages": [],
                "curr_func_call": (func_call, args),
                "tasks": [],
                "func_call_results": None,
                "past_steps": [],
            }
        )
        return {
            "func_call_results": output.func_call_result,
            "next_node": "CB",
            "last_node": "CB",
        }


# TODO
def CheckFilter(state: State):

    return {"messages": state["messages"]}


# class ToolNode:
#     def __init__(self, tools: list) -> None:
#         self.tools_by_name = {tool.name: tool for tool in tools}

#     def __call__(self, inputs: dict):
#         if messages := inputs.get("messages", []):
#             message = messages[-1]
#         else:
#             raise ValueError("No message found in input")
#         outputs = []
#         for tool_call in message.tool_calls:
#             tool_result = self.tools_by_name[tool_call["name"]].invoke(
#                 tool_call["args"]
#             )
#             outputs.append(
#                 ToolMessage(
#                     content=json.dumps(tool_result),
#                     name=tool_call["name"],
#                     tool_call_id=tool_call["id"],
#                 )
#             )
#         return {"messages": outputs, "last_node": "Tools"}


tool_node = ToolNode(tools=[tool])
graph_builder = StateGraph(State)
# graph_builder.add_node("Tools", tool_node)
graph_builder.add_node("CTF", CheckTaintFlow)
graph_builder.add_node("CB", CheckBranch)
graph_builder.add_node("CF", CheckFilter)


def route(
    state: State,
):
    if messages := state.get("messages", []):
        ai_message = messages[-1]
    else:
        raise ValueError(f"No messages found in input state to tool_edge: {state}")
    if hasattr(ai_message, "tool_calls") and len(ai_message.tool_calls) > 0:
        return "Tools"
    else:
        return state.get("next_node")


graph_builder.add_edge(START, "CTF")
graph_builder.add_conditional_edges("CTF", route, {"CB": "CB", END: END})
graph_builder.add_conditional_edges("CB", route, {"CF": END, END: END, "CB": "CB"})
graph_builder.add_edge("reActCB", "subCB")
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
