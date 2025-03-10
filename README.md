# 调用链检查

Input: 函数，source, sink
Step:
    a. 判断 source 到 sink 之间是否可以连同
    b. 判断 source 的参数最终流入 sink中的哪些参数当中。
Output: 调用链, sink可控参数


# 分支检查

input: 函数，source, sink，调用链
Step:
    a. 定位调用链上的所有分支判断语句，分析要使得调用链流通该如何取值
    b. 
        1. 提取所有函数调用
        2. 判断参数是否可控， 是3，否5
        3. 传入llm和tools, 自主思考和判断函数是否可以取值true 和 false
        4. cache判断结果。
        5. 下结论（true, false，true or false）。若是参数不可控，结论为true or false
    c. 总结，该调用链在xxx参数可控的情况下能否绕过分支检查/不存在分支检查
Ouput: 无


# 安全检查

input: 函数，source, sink，调用链
Step:
    a. 定位调用链上的所有安全检查
    b. 
        1. 提取所有安全检查
        2. 传入llm和tools, 自主思考和判断函数是否有安全检查，有:3 , 无: 5
        3. 反思，有无可能绕过安全检查
        4. cache判断结果。
        5. 下结论（安全检查？绕过？）。
    c. 总结，该调用链能否绕过安全检查/不存在安全检查
Ouput: 无