from typing import TypedDict
from langgraph.graph import StateGraph, START, END

class State(TypedDict):
    val: str

def a(s): return {"val": s.get("val","") + "A"}
def b(s): return {"val": s.get("val","") + "B"}
def c(s): return {"val": s.get("val","") + "C"}

workflow = StateGraph(State)
workflow.add_node("a", a)
workflow.add_node("b", b)
workflow.add_node("c", c)

workflow.add_edge(START, "a")
workflow.add_edge(START, "b")
try:
    workflow.add_edge(["a", "b"], "c")
    print("List syntax works!")
except Exception as e:
    print("Error:", e)
    
workflow.add_edge("c", END)
app = workflow.compile()
print(app.invoke({"val": ""}))
