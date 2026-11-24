import importlib.util, json, sys, copy
spec = importlib.util.spec_from_file_location("candidate", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
results = []
for case in json.load(sys.stdin):
    store = {}; observations = []
    for op in case["operations"]:
        try:
            value = m.authorize(op[1]) if op[0] == "authorize" else m.register(store, op[1], op[2])
            observations.append({"value":copy.deepcopy(value),"store":copy.deepcopy(store)})
        except Exception as e:
            observations.append({"error":type(e).__name__,"store":copy.deepcopy(store)})
    results.append(observations)
print(json.dumps(results, sort_keys=True, allow_nan=False))
