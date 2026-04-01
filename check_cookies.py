import json, time

with open("/home/malrangme/.ctf-browser-state.json") as f:
    d = json.load(f)

now = time.time()
dh = [c for c in d.get("cookies", []) if "dreamhack" in c.get("domain", "")]
print(f"Dreamhack cookies: {len(dh)}")
for c in dh:
    exp = c.get("expires", -1)
    expired = "EXPIRED" if (exp > 0 and exp < now) else "valid"
    print(f"  {c['name']}: {expired} (expires={exp})")
