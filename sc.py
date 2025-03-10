#
# from utils import get_func

# code = get_func(
#     "com.thingclips.smart.rnplugin.trctjsbundleloadermanager.TRCTJSBundleLoaderManager#loadJsBundle",
#     "tuya",
# )
# print(code)

from agent.graph import graph
from utils import init_state, get_func


def stream_graph_updates():
    func_content = get_func(
        "com.xiaomi.smarthome.framework.plugin.rn.nativemodule.MIOTPersistModuleCore#copyFile",
        "mihome",
    )

    source_arg = "params"
    sink_func = "lambda$copyFile$9"
    state = init_state(func_content, source_arg, sink_func)
    # print(graph.stream(state))
    # print(graph.stream(state))
    messages = None
    for event in graph.stream(state):
        # print("Event:", event)
        for value in event.values():
            messages = value["messages"]

    for m in messages:
        print(m.content)
        print("\n\n")


stream_graph_updates()
