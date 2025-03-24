from langchain import hub
from langchain_openai import ChatOpenAI
import operator
from config import api_key, base_url, api_key1, base_url1
from typing import Annotated, List, Tuple
from typing_extensions import TypedDict
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field
from typing import Union
from typing import Literal
from langgraph.graph import END
from langgraph.graph import StateGraph, START
from tools.get_function import GetFuncTool
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_core.prompts import ChatPromptTemplate

# Choose the LLM that will drive the agent
agent1 = ChatOpenAI(api_key=api_key1, base_url=base_url1, model="gpt-4o-latest")
prompt = "You are a helpful assistant."
agent_executor = create_react_agent(
    agent1, [GetFuncTool(target="mihome")], prompt=prompt
)


class CheckBranchState(TypedDict):
    input: str
    tasks: List[str]
    past_steps: Annotated[List[Tuple], operator.add]
    response: str
    messages: List[str]


class Plan(BaseModel):
    steps: List[str] = Field(
        description="different steps to follow, should be in sorted order"
    )


planner_prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            """For the given objective, come up with a simple step by step plan. \
This plan should involve individual tasks, that if executed correctly will yield the correct answer. Do not add any superfluous steps. \
The result of the final step should be the final answer. Make sure that each step has all the information needed - do not skip steps.""",
        ),
        ("placeholder", "{messages}"),
    ]
)
planner = planner_prompt | ChatOpenAI(
    api_key=api_key1, base_url=base_url1, model="o3-mini", temperature=0
).with_structured_output(Plan)


class Response(BaseModel):
    """Response to user."""

    response: str


class Act(BaseModel):
    """Action to perform."""

    action: Union[Response, Plan] = Field(
        description="Action to perform. If you want to respond to user, use Response. "
        "If you need to further use tools to get the answer, use Plan."
    )


replanner_prompt = ChatPromptTemplate.from_template(
    """For the given objective, come up with a simple step by step plan. \
This plan should involve individual tasks, that if executed correctly will yield the correct answer. Do not add any superfluous steps. \
The result of the final step should be the final answer. Make sure that each step has all the information needed - do not skip steps.

Your objective was this:
{input}

Your original plan was this:
{plan}

You have currently done the follow steps:
{past_steps}

Update your plan accordingly. If no more steps are needed and you can return to the user, then respond with that. Otherwise, fill out the plan. Only add steps to the plan that still NEED to be done. Do not return previously done steps as part of the plan."""
)


replanner = replanner_prompt | ChatOpenAI(
    model="o3-mini",
    temperature=0,
    api_key=api_key1,
    base_url=base_url1,
).with_structured_output(Act)


async def execute_step(state: CheckBranchState):
    plan = state["plan"]
    plan_str = "\n".join(f"{i+1}. {step}" for i, step in enumerate(plan))
    task = plan[0]
    task_formatted = f"""For the following plan:
{plan_str}\n\nYou are tasked with executing step {1}, {task}."""
    agent_response = await agent_executor.ainvoke(
        {"messages": [("user", task_formatted)]}
    )
    return {
        "past_steps": [(task, agent_response["messages"][-1].content)],
    }


async def plan_step(state: CheckBranchState):
    plan = await planner.ainvoke({"messages": [("user", state["input"])]})
    return {"plan": plan.steps}


async def replan_step(state: CheckBranchState):
    output = await replanner.ainvoke(state)
    if isinstance(output.action, Response):
        return {"response": output.action.response}
    else:
        return {"plan": output.action.steps}


def should_end(state: CheckBranchState):
    if "response" in state and state["response"]:
        return END
    else:
        return "agent"


workflow = StateGraph(CheckBranchState)

# Add the plan node
workflow.add_node("planner", plan_step)

# Add the execution step
workflow.add_node("agent", execute_step)

# Add a replan node
workflow.add_node("replan", replan_step)

workflow.add_edge(START, "planner")

# From plan we go to agent
workflow.add_edge("planner", "agent")

# From agent, we replan
workflow.add_edge("agent", "replan")

workflow.add_conditional_edges(
    "replan",
    # Next, we pass in the function that will determine which node is called next.
    should_end,
    ["agent", END],
)

# Finally, we compile it!
# This compiles it into a LangChain Runnable,
# meaning you can use it as you would any other runnable
app = workflow.compile()
