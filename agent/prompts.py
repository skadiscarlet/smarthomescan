from typing import Union
from pydantic import BaseModel, Field, model_validator
from my_types import Response


class CTF_OUT(BaseModel):
    reachable: bool = Field(
        description="Is there a possible data flow from source to sink?"
    )
    flow: str = Field(
        description="If there is no feasible data flow, fill in the empty string. If there is a feasible data flow, fill in the specific flow process, in the form of `$1->$2->$3->.....->$n`, where `$1` is the source, `$n` is the sink, and `$k` represents the variables or function calls passed in the middle."
    )

    @model_validator(mode="after")
    def check(self):
        if self.reachable and self.flow == "":
            raise ValueError("flow is not filled in when reachable is True")
        return self


template4CTF = """
You need to trace the data flow within a function. I will provide you with a series of parameteers and a sink (which is a function call). You need to determine whether the content of the specified parameters flows into the target function call when it is invoked.

note: You only need to determine if the data flow is potentially possible, without worrying about whether there are filtering functions, security checks, or branch conditions in between. You just need to judge whether it is possibl to establish a data flow from source to sink under any possible circumstances.


### function content ###
The specific content of the function.
```java
{function_content}
```

###  source arg  ###
the source args to be traced.
```
{source_arg}
```
###  sink func-calling  ###
the sink function call.

{sink_call}
"""


class CB1_OUT(BaseModel):
    need_check: bool = Field(
        description="If there are no branch conditions worth analyzing in the provided tainted flow, fill in 'false'; otherwise, fill in 'true'."
    )


template4CB1 = """
You are a code auditing expert who needs to audit the branch statements (such as if and switch) in the given tainted data propagation path to determine whether the malicious data flow can correctly reach the endpoint and bypass any potential security checks. You only need to focus on the conditional checks of the branch statements, and there is no need to consider other filtering functions along the path for now. You need to follow my instructions step by step to complete the task. 

Now first, you need to locate all branch decision statements in the call chain. If no branch decision statements exist, return need_check as false; otherwise, set need_check to true, and consider what values each logical condition in the decision statement should take to ensure the flow continues through the call chain.


### function content ###
The specific content of the function.
```java
{function_content}
```

###  source arg  ###
the source args to be traced.
```
{source_arg}
```
###  sink func-calling  ###
the sink function call.

{sink_call}

###  tainted flow  ###

{tainted_flow}
"""


class CB2_OUT(BaseModel):
    func_call_dict: dict = Field(
        description="The list of function calls and it's controllable parameter names in the conditional statements. etc {'xxx.xxx.xxx.xxx#func1': ['param name1', 'param name2'], 'xxx.xxx.xxx.xxx#func2': ['param name3']}. If there are no function calls in the conditional statements, fill in an empty dictionary."
    )


template4CB2 = """
To determine whether the decision statements in conditional branches will perform security checks on our parameters, we first need to audit the decision logic within the conditional statements. If there are any function calls that might be used for security checks, we need to understand the details of these functions and whether their parameters are controllable (i.e., whether there is a data flow from the source to the parameters). Therefore, please provide the names of the security-checking functions present in the conditional statements and the names of the parameters that can be controlled.

"""


class CB3_OUT(BaseModel):
    reachable: bool = Field(
        description="whether the tainted data propagation path can successfully pass through the conditional checks of the branch statements"
    )


template4CB3 = """
Based on all the information provided above, determine whether the tainted data propagation path can successfully pass through the conditional checks of the branch statements?

Note: You need to consider whether each inspection function can be bypassed and their logical connections. For instance, if the inspection statement is a() || b() where a can be bypassed but b cannot, then the statement can still be passed.

"""


class subCB1_OUT(BaseModel):
    tasks: list[str] = Field(
        description="different steps to follow, should be in sorted order"
    )


template4subCB1 = """
As a security audit expert, you are now tasked with auditing a potential security-check function during a taint analysis process. Given that the parameter {parameters_name} can be controlled by an attacker, you need to autonomously and step-by-step review whether the function {function_name} performs a security check on the parameters we pass in. You may use tools to retrieve the specific content of other functions called within this function and comprehensively examine the security-check elements contained therein. If this function does perform a security check, you also need to carefully evaluate whether it can be bypassed, with some examples of bypassable cases shown below. Finally, you are required to mimic a human's approach and provide your plan step-by-step. This plan should involve individual tasks, that if executed correctly will yield the correct answer. Do not add any superfluous steps. 
The result of the final step should be the final answer. Make sure that each step has all the information needed - do not skip steps.


### bypassable cases ###

- The passed parameter is a path, and the function checks its beginning using methods like startswith, but it does not account for the possibility of bypassing with '..'.
- The passed parameter is a path, and the function adds a prefix path to it; however, it does not account for the possibility of bypassing with '..'.
- The passed parameter is a URL, and the function checks whether it contains a specific domain name, such as requiring it to include 'abc.com'. However, it does not account for the possibility of a format like 'abc.com.hack.vip'.


### function content ###
The specific content of the function.
```java
{function_content}
```


"""


class subCB2_OUT(BaseModel):
    action: Union[Response, subCB1_OUT] = Field(
        description="Action to perform. If you want to respond to user, use Response. "
        "If you need to further use tools to get the answer, use Plan."
    )


template4subCB2 = """

For the given objective, come up with a simple step by step plan. \
This plan should involve individual tasks, that if executed correctly will yield the correct answer. Do not add any superfluous steps. \
The result of the final step should be the final answer. Make sure that each step has all the information needed - do not skip steps.

Your objective was this:

```text'
As a security audit expert, you are now tasked with auditing a potential security-check function during a taint analysis process. Given that the parameter {parameters_name} can be controlled by an attacker, you need to autonomously and step-by-step review whether the function {function_name} performs a security check on the parameters we pass in. You may use tools to retrieve the specific content of other functions called within this function and comprehensively examine the security-check elements contained therein. If this function does perform a security check, you also need to carefully evaluate whether it can be bypassed, with some examples of bypassable cases shown below. Finally, you are required to mimic a human's approach and provide your plan step-by-step. This plan should involve individual tasks, that if executed correctly will yield the correct answer. Do not add any superfluous steps. 
The result of the final step should be the final answer. Make sure that each step has all the information needed - do not skip steps.
```

Your original plan was this:
{tasks}

You have currently done the follow steps:
{past_steps}

Update your plan accordingly. If no more steps are needed and you can return to the user, then respond with that. Otherwise, fill out the plan. Only add steps to the plan that still NEED to be done. Do not return previously done steps as part of the plan.

"""
