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
    CB3_OUT,
    template4CB3,
    template4subCB1,
    subCB2_OUT,
    template4subCB2,
)
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts import PromptTemplate, StringPromptTemplate
from my_types import State

# os.environ["OPENAI_API_KEY"] = api_key
# os.environ["DEEPSEEK_API_KEY"] = api_key
# os.environ["DEEPSEEK_API_BASE"] = base_url
# agent1 = ChatOpenAI(api_key=api_key1, model="gpt-4o", base_url=base_url1)
agent1 = ChatOpenAI(api_key=api_key, model="qwen-plus", base_url=base_url)
agent2 = ChatOpenAI(api_key=api_key, model="qwen-plus", base_url=base_url)
agent3 = ChatOpenAI(api_key=api_key, model="qwen-max", base_url=base_url)


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
        "next_node": "CB" if output.reachable else END,
        "last_node": "CTF",
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
        if not output.need_check:
            return {
                "messages": messages + [response],
                "next_node": "CF",
                "last_node": "CB",
            }

        else:
            parser = PydanticOutputParser(pydantic_object=CB2_OUT)
            prompt = PromptTemplate(
                template=template4CB2,
                partial_variables={
                    "format_instructions": parser.get_format_instructions()
                },
            ).format()

            messages = state["messages"]
            messages.append(HumanMessage(content=prompt))
            response = agent2.invoke(messages)
            output = parser.parse(response.content)
            return {
                "messages": messages + [response],
                "next_node": "CB",
                "func_call_dict": output.func_call_dict,
                "last_node": "CB",
            }

    if len(state.get("func_call_dict")) <= 0:
        parser = PydanticOutputParser(pydantic_object=CB3_OUT)
        prompt = PromptTemplate(
            template=template4CB3,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        ).format()
        messages = state["messages"]
        messages.append(HumanMessage(content=prompt))
        response = agent2.invoke(messages)
        output = parser.parse(response.content)

        return {
            "messages": messages + [response],
            "reachable": output.reachable,
            "next_node": "CF" if output.reachable else END,
            "last_node": "CB",
        }
    else:
        func_call, args = state["func_call_dict"].popitem()
        # TODO: 利用缓存结果
        return {
            "messages": state["messages"],
            "curr_func_call": (func_call, args),
            "next_node": "subCB",
            "last_node": "CB",
        }


def subCheckBranch(state: State):
    if state.get("last_node") == "subCB":
        parser = PydanticOutputParser(pydantic_object=subCB2_OUT)
        messages = state["messages"]
        prompt = PromptTemplate(
            template=template4subCB2,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        ).format()
        # TODO：缓存检查结果
        messages.append(HumanMessage(content=prompt))
        response = agent3.invoke(messages)
        return {
            "messages": messages + [response],
            "last_node": "subCB",
            "next_node": "CB",
        }

    if state.get("last_node") == "CB":
        messages = state["messages"]
        func_call, args = state["curr_func_call"]
        prompt = PromptTemplate(
            template=template4subCB1,
            input_variables=["function_name", "parameters_name"],
        ).format(function_name=func_call, parameters_name=", ".join(args))
        messages.append(HumanMessage(content=prompt))
        response = agent3.invoke(messages)
    elif state.get("last_node") == "Tools":
        messages = state["messages"]
        messages.append(
            HumanMessage(content="Tools success. Now, continue to your task")
        )
        response = agent3.invoke(messages)
    return {
        "messages": messages + [response],
        "last_node": "subCB",
        "next_node": "subCB",
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
        return {"messages": outputs, "last_node": "Tools"}


tool_node = ToolNode(tools=[tool])
graph_builder = StateGraph(State)
graph_builder.add_node("Tools", tool_node)
graph_builder.add_node("CTF", CheckTaintFlow)
graph_builder.add_node("CB", CheckBranch)
graph_builder.add_node("subCB", subCheckBranch)
graph_builder.add_node("CF", CheckFilter)
graph_builder.add_node("subCF", subCheckFilter)


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
graph_builder.add_conditional_edges(
    "CB", route, {"CF": END, "subCB": "subCB", END: END, "CB": "CB"}
)  # test for CB
graph_builder.add_conditional_edges(
    "subCB", route, {"CB": "CB", "subCB": "subCB", "Tools": "Tools"}
)
graph_builder.add_conditional_edges(
    "Tools", route, {"subCB": "subCB", "subCF": "subCF"}
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
