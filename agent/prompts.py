from pydantic import BaseModel, Field, model_validator


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
You need to trace the data flow within a function. I will provide you with a series of parameters and a sink (which is a function call). You need to determine whether the content of the specified parameters flows into the target function call when it is invoked.

note: You only need to determine if the data flow is potentially possible, without worrying about whether there are filtering functions, security checks, or branch conditions in between. You just need to judge whether it is possible to establish a data flow from source to sink under any possible circumstances.


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

### OUTPUT FORMAT ###
{format_instructions}
"""


class CB1_OUT(BaseModel):
    need_check: bool = Field(
        description="If there are no branch conditions worth analyzing in the provided tainted flow, fill in 'false'; otherwise, fill in 'true'."
    )


template4CB1 = """
You are a code auditing expert who needs to audit the branch statements (such as if and switch) in the given tainted data propagation path to determine whether the malicious data flow can correctly reach the endpoint and bypass any potential security checks. You only need to focus on the conditional checks of the branch statements, and there is no need to consider other filtering functions along the path for now. You need to follow my instructions step by step to complete the task. 

Now first, you need to locate all branch decision statements in the call chain. If no branch decision statements exist, return need_check as false; otherwise, set need_check to true, and consider what values each logical condition in the decision statement should take to ensure the flow continues through the call chain.

Note: Your output must format as '### OUTPUT FORMAT ###' specifies.

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

### OUTPUT FORMAT ###
{format_instructions}
"""


class CB2_OUT(BaseModel):
    func_call_dict: dict = Field(
        description="The list of function calls and it's controllable parameter names in the conditional statements. etc {'func1': ['param name1', 'param name2'], 'func2': ['param name3']}. If there are no function calls in the conditional statements, fill in an empty dictionary."
    )


template4CB2 = """
To determine whether the decision statements in conditional branches will perform security checks on our parameters, we first need to audit the decision logic within the conditional statements. If there are any function calls that might be used for security checks, we need to understand the details of these functions and whether their parameters are controllable (i.e., whether there is a data flow from the source to the parameters). Therefore, please provide the names of the security-checking functions present in the conditional statements and the names of the parameters that can be controlled.

### OUTPUT FORMAT ###
{format_instructions}
"""


class CB3_OUT(BaseModel):
    reachable: bool = Field(
        description="whether the tainted data propagation path can successfully pass through the conditional checks of the branch statements"
    )


template4CB3 = """
Based on all the information provided above, determine whether the tainted data propagation path can successfully pass through the conditional checks of the branch statements?

### OUTPUT FORMAT ###
{format_instructions}
"""


template4subCB1 = """
Next, please autonomously audit step by step whether function {function_name} will perform a security check on the parameters we pass in, under the condition that parameters {parameters_name} is controllable. You need to use a tool to obtain the specific content of the function and independently deduce the security review elements within it. During this process, you can interact with the environment to retrieve more information about the function, enabling you to make a well-founded judgment.
"""


class subCB2_OUT(BaseModel):
    security_check: bool = Field(
        description="Whether there is a security check in the function."
    )
    bypass: bool = Field(
        description="Whether the security check can be bypassed. fill in false if security check does not exist."
    )


template4subCB2 = """
If you determine that a security check exists, please reflect on whether it can be bypassed using current security techniques. Enter the result into the bypass field of the output. If no security check exists, the default value of bypass should be false.

### OUTPUT FORMAT ###
{format_instructions}
"""
