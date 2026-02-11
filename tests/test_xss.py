import re

xss_rule = re.compile(r"(?i)(<\s*script|javascript\s*:|alert\s*\()")


def waf_check(data):
    return "BLOCKED" if xss_rule.search(data) else "ALLOWED"


with open("payloads.txt", "r", encoding="utf-8") as f:
    payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]


for p in payloads:
    print(p, "=>", waf_check(p))
