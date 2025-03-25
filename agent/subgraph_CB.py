import json
from config import api_key, base_url, api_key1, base_url1
from utils import get_func
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import AIMessage, HumanMessage
from langchain_openai import ChatOpenAI
from tools.get_function import GetFuncTool
from langgraph.prebuilt import create_react_agent
from agent.prompts import (
    subCB1_OUT,
    template4subCB1,
    subCB2_OUT,
    template4subCB2,
    template4subCB3,
)
from my_types import SubState, Response

llm1 = ChatOpenAI(api_key=api_key1, model="gpt-4o-2024-08-06", base_url=base_url1)
llm2 = ChatOpenAI(api_key=api_key1, model="o3-mini", base_url=base_url1)
llm3 = ChatOpenAI(api_key=api_key1, model="o3-mini", base_url=base_url1)

tool = GetFuncTool(target="mihome")
tools = [tool]
analyzer = llm1
planner = llm2.bind_tools(tools)
executor = create_react_agent(llm3, [GetFuncTool(target="mihome")], prompt="")


def plan_step(state: SubState):
    function_name, args = state["curr_func_call"]
    prompt = template4subCB1.format(
        parameters_name=", ".join(args),
        function_name=function_name,
        function_content=get_func(function_name, "mihome"),
    )
    messages = [HumanMessage(content=prompt)]
    output = planner.with_structured_output(subCB1_OUT).invoke(messages)
    return {
        "tasks": output.tasks,
        "messages": messages.append(AIMessage(content=json.dumps(output))),
    }


def replan_step(state: SubState):
    function_name, args = state["curr_func_call"]
    prompt = template4subCB2.format(
        tasks=json.dumps(state["tasks"]),
        past_steps=json.dumps(state["past_steps"]),
        parameters_name=", ".join(args),
        function_name=function_name,
    )
    # TODO：缓存检查结果
    messages = [HumanMessage(content=prompt)]
    output = planner.with_structured_output(subCB2_OUT).invoke(messages)
    if isinstance(output.action, Response):
        return {
            "func_call_result": output.action.response,
        }
    else:
        return {
            "tasks": output.action.tasks,
            "messages": messages.append(AIMessage(content=json.dumps(output))),
        }


def execute_step(state: SubState):
    tasks = state["tasks"]
    task = "\n".join(f"{i+1}. {step}" for i, step in enumerate(tasks))
    task = tasks.pop(0)
    prompt = template4subCB3.format(
        plan_str=task,
        num=json.dumps(state["past_steps"]),
        task=task,
    )
    messages = state["messages"].append(HumanMessage(content=prompt))
    agent_response = executor.invoke({"messages": messages})
    return {
        "messages": messages + agent_response["messages"],
        "past_steps": [(task, agent_response["messages"][-1].content)],
        "tasks": tasks,
    }


def task_end(state: SubState):

    if len(state["tasks"]) > 0:
        return "agent"
    else:
        return "replan"


def should_end(state: SubState):
    if "response" in state and state["response"]:
        return END
    else:
        return "agent"


subgraph = StateGraph(SubState)

subgraph.add_node("planner", plan_step)
subgraph.add_node("agent", execute_step)
subgraph.add_node("replan", replan_step)
subgraph.add_edge(START, "planner")
subgraph.add_edge("planner", "agent")
subgraph.add_conditional_edges("agent", task_end, ["replan", "agent"])
subgraph.add_conditional_edges(
    "replan",
    should_end,
    ["agent", END],
)
subgraph = subgraph.compile()
