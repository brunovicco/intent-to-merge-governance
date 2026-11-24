"""Trusted synthetic candidates and acceptance harness. Not an LLM or sandbox."""
AUTH = '''def authorize(role):
    return role == "payment-operator"

'''
BASE = AUTH + '''def register(store, key, amount):
    payment = {"id": len(store) + 1, "amount": amount}
    store[key] = payment
    return payment
'''
PARTIAL = AUTH + '''def register(store, key, amount):
    if amount <= 0:
        raise ValueError("invalid amount")
    if key in store:
        return store[key]
    payment = {"id": len(store) + 1, "amount": amount}
    store[key] = payment
    return payment
'''
FIXED = PARTIAL.replace('        return store[key]', '        if store[key]["amount"] != amount:\n            raise ValueError("conflicting payload")\n        return store[key]')
DRIFTED = FIXED.replace('return role == "payment-operator"', 'return True')
SIGNATURE_DRIFT = FIXED.replace('def register(store, key, amount):', 'def register(store, key, amount, optional=None):')
IMPORT_DRIFT = "import math\n" + FIXED
BROKEN = BASE + '\n# alternate candidate with no improvement\n'
HARNESS = '''import importlib.util, json, sys
from pathlib import Path
p = Path(sys.argv[1]) / "app/payments.py"
spec = importlib.util.spec_from_file_location("candidate", p)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
def invalid():
    try: m.register({}, "a", 0)
    except ValueError: return True
    return False
def same():
    s = {}; a = m.register(s, "a", 10); b = m.register(s, "a", 10)
    return a == b and len(s) == 1
def distinct():
    s = {}; a = m.register(s, "a", 10); b = m.register(s, "b", 10)
    return a["id"] != b["id"] and len(s) == 2
def conflict():
    s = {}; a = m.register(s, "a", 10)
    try: m.register(s, "a", 20)
    except ValueError: return s["a"] == a and len(s) == 1
    return False
checks = dict(positive_amount=invalid, same_key_same_payment=same, distinct_keys=distinct, conflicting_payload=conflict)
result = {}
for name, fn in checks.items():
    try: result[name] = fn() is True
    except Exception: result[name] = False
print(json.dumps(result, sort_keys=True))
'''
