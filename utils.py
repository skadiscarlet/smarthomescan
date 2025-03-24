from config import decompileDir, JAVA_PATH
import os
import subprocess
from my_types import FuncCallNode, FuncArg, UnknownError, State
import re
from log import log
from langchain_core.messages import SystemMessage


def init_state(func_content, source_arg, sink_func) -> State:
    """
    Returns the initial state for the StateGraph.

    Returns:
        State: The initial state with default values.
    """
    return State(
        messages=[
            SystemMessage(
                content="You are a cybersecurity code auditing assistant who needs to provide assistance based on tasks specified by the user. If the user's input includes ### OUTPUT FORMAT ###, you must provide the response in the specified format as required by the user."
            )
        ],
        reachable=True,
        flow="",
        function_content=func_content,
        source_arg=source_arg,
        sink_call=sink_func,
        next_node=None,
        last_node=None,
        curr_func_call=None,
        func_call_dict={},
    )


def funcsign2node(func_str, target):
    """
    Parses a function ssign and retrieves its details from the target to a FuncCallNode.

    Args:
        func_str (str): The function string in the format "<class_name: ret_type func_name(arg_types)>".
        target (str): The target source from which to retrieve the function content.

    Returns:
        FuncCallNode: An object containing the parsed function details including:
            - func_name (str): The fully qualified function name (class_name#func_name).
            - func_args (List[FuncArg]): A list of function arguments with their names and types.
            - func_ret_type (str): The return type of the function.
            - func_content (str): The content of the function.

    Raises:
        ValueError: If the function string format is invalid.
    """

    log.info("parse function: " + func_str + " in " + target)
    pattern = r"<([\w.$]+):\s*([^ ]+)\s+([\w$]*)\((.*?)\)>"
    match = re.search(pattern, func_str)

    if not match:
        raise UnknownError("Invalid function string format")

    class_name, ret_type, func_name, arg_type_str = match.groups()
    func_content = get_func(class_name + "#" + func_name, target)
    log.debug("function content: \n" + func_content + "\n\n")
    match = re.search(r"\((.*?)\)", func_content)
    arg_str = None
    if match:
        arg_str = match.group(1)
    func_args = []
    if arg_str is not None:
        for index in range(len(arg_str.split(","))):
            arg_s = arg_str.split(",")[index]
            arg_type = arg_type_str.split(",")[index]
            arg_name = arg_s.strip().split(" ")[-1]
            func_args.append(FuncArg(arg_name=arg_name, arg_type=arg_type))
    return FuncCallNode(
        func_name=class_name + "#" + func_name,
        func_args=func_args,
        func_ret_type=ret_type,
        func_content=func_content,
    )


def get_func(full_path: str, target: str):
    """
    Retrieves the content of a function from a target source file.
    Args:
        full_path (str): The full path of the function in the format 'ClassName#FunctionName'.
        target (str): The target directory or identifier for the source file.
    Returns:
        str: The content of the function if found, otherwise an error message.
    Raises:
        Exception: If there is an error in processing the function retrieval.
    Notes:
        - The function uses a subprocess to call a Java parser to retrieve the function content.
        - The function handles different cases for class names with inner classes denoted by '$'.
        - If the function is a constructor, it adjusts the function name accordingly.
    """
    try:
        tmp = full_path.split("#")

        dirName = decompileDir + target + os.sep + tmp[0].replace(".", os.sep) + ".java"
        func_str = tmp[1].strip()

        fullClassName = tmp[0]
        dollarCount = fullClassName.count("$")
        if dollarCount == 0:
            filename = dirName
            if not os.path.exists(filename):
                return "error: this is a native function"
            className = fullClassName

        elif dollarCount == 1:
            filename = dirName.split("$")[0] + ".java"
            if not os.path.exists(filename):
                return "error: this is a native function"

            className = fullClassName.replace("$", ".")
        else:
            filename = dirName
            if os.path.exists(filename):
                className = fullClassName
            else:
                filename = dirName.split("$")[0] + ".java"
                if os.path.exists(filename):
                    className = fullClassName.replace("$", ".")
                else:
                    log.error("error find class file " + full_path)
                    return "error: this func you want to find is not exist"
        funcName = func_str
        if "<init>" in full_path:
            funcName = className.split(".")[-1]

    except Exception as e:
        return "error: this func you want to find is not exist"

    command = [
        JAVA_PATH,
        "-jar",
        "getfunction.jar",
        filename,
        funcName,
        className,
        "get_func",
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout = process.communicate()

    if stdout[1] != b"":
        log.debug("get_func    " + full_path + "     " + stdout[1].decode("gbk"))
        return "error: this func you want to find is not exist"
    elif stdout[0] == b"":
        log.debug("error find function " + full_path)
        return "error: this func you want to find is not exist"
    else:
        out = stdout[0].decode("utf-8")
        with open(filename, "r") as fp:
            content = fp.read()
            imports = re.findall(r"import (.*);", content)
            imports = list(filter(lambda x: x.split(".")[-1] in out, imports))

        return "\n".join([f"import {imp};" for imp in imports]) + "\n" + out
