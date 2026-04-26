import re
from typing import NamedTuple
from .normalizer import recursive_normalize


class DetectionResult(NamedTuple):
    is_xss: bool
    score: int
    triggered_rules: list[str]


class XSSDetector:
    """
    XSS detector with multi-layer normalization and structured rule scoring.
    v2: Added .call/.apply, bare on* attributes, indirect invocation, null-byte handling
    """

    RULES: list[tuple[str, int, str]] = [
        # Script tags (highest priority)
        (r"<\s*script\b[^>]*>", 28, "script_open_tag"),
        (r"</\s*script\s*>", 28, "script_close_tag"),
        (r"<\s*script[^>]*>.*?</\s*script\s*>", 30, "script_full"),
        
        # JS / data URIs
        (r"javascript\s*:", 25, "js_protocol"),
        (r"data\s*:\s*(?:text/html|application/xhtml)", 22, "data_html_uri"),
        (r"vbscript\s*:", 22, "vbscript_protocol"),
        (r"file\s*://", 20, "file_protocol"),
        
        # DOM sinks (critical execution points)
        (r"\b(?:inner|outer)HTML\s*(?:\+?=|\()", 20, "dom_sink_html"),
        (r"\bdocument\.write\s*\(", 20, "dom_sink_write"),
        (r"\blocation(?:\.href)?\s*=", 18, "location_sink"),
        (r"\bevaluate\s*\(", 20, "evaluate_sink"),
        
        # Event handlers on tags (comprehensive — covers all HTML5 + legacy events)
        # Pattern 1: named common events
        (
            r"<[^>]*\bon(?:error|load|click|mouse\w+|key\w+|focus|blur|change|submit|reset|input|drag\w*|pointer\w*|animation\w*|transition\w*|wheel|copy|paste|cut|select|scroll|before|after|dblclick|contextmenu|touch\w+|activate|begin|end|repeat|seek|toggle|start|finish|close|open|play|pause|ended|stalled|suspend|waiting|seeked|seeking|timeupdate|volumechange|message|storage|hashchange|popstate|resize|unload|pageshow|pagehide|online|offline|fullscreen\w*|gotpointercapture|lostpointercapture|invalid|cuechange)\s*=",
            22,
            "event_handler_tag",
        ),
        # Pattern 2: catch-all for any on<word> event inside a tag (handles unknown/future events)
        (
            r"<[^>]*\bon[a-z]{2,20}\s*=",
            20,
            "event_handler_catch_all",
        ),

        # Bare on* attribute without enclosing tag (catch-all)
        (
            r"\bon[a-z]{2,20}\s*=\s*[\"']?[\(`]",
            18,
            "bare_event_handler",
        ),
        
        # Dangerous functions (execution)
        (r"\beval\s*\(", 22, "eval_call"),
        (r"\b(?:set(?:Timeout|Interval)|Function)\s*\(", 15, "deferred_exec"),
        (r"\batob\s*\(", 12, "base64_decode"),
        (r"\b(?:alert|prompt|confirm)\s*\(", 12, "dialog_call"),
        (r"\bwindow\.location\s*=", 18, "window_location"),
        (r"\bwindow\.open\s*\(", 15, "window_open"),
        
        # .call() / .apply() / .bind() on dangerous functions
        (
            r"\b(?:alert|prompt|confirm|eval)\s*\.\s*(?:call|apply|bind)\s*\(",
            20,
            "func_call_apply",
        ),
        
        # Indirect invocation patterns
        (
            r"\((?:alert|prompt|confirm|eval)\)\s*[\(\`]",
            17,
            "indirect_invoke",
        ),
        
        # Array constructor + constructor access
        (r"\[.*\]\.constructor\b", 18, "array_constructor"),
        (r"\(\)\.constructor\b", 18, "function_constructor"),
        
        # Dangerous tags
        (r"<\s*(?:iframe|object|embed|applet)\b", 20, "embed_tag"),
        (r"<\s*(?:iframe|object|embed|applet)[^>]*\b(?:src|data|code)\s*=", 22, "embed_src"),
        
        # SVG/Math vectors
        (r"<\s*(?:svg|math)\b[^>]*(?:on\w+|href)\s*=", 20, "svg_event"),
        (r"<\s*svg[^>]*>", 18, "svg_tag"),
        (r"<\s*(?:set|animate|image)\b[^>]*on", 18, "svg_animate"),
        
        # Media tags with dangerous src
        (
            r"<\s*(?:img|video|audio|source)\b[^>]*\bsrc\s*=\s*[\"']?\s*(?:javascript|data)\s*:",
            22,
            "media_js_src",
        ),
        (r"<[^>]+\bsrc\s*=\s*[\"']?[^\"'>\s]*javascript", 20, "img_js_src_attr"),
        
        # Dangerous attributes (not tag-bound)
        (r"\bstyle\s*=\s*[\"'].*expression\s*\(", 18, "css_expression"),
        (r"\bstyle\s*=\s*[\"'].*javascript", 18, "style_js"),
        (r"\bbackground\s*=\s*[\"']?javascript", 18, "bg_js"),
        
        # Form action + formmethod
        (r"\bformaction\s*=\s*[\"']?\s*javascript", 20, "formaction_js"),
        (r"\baction\s*=\s*[\"']?javascript", 18, "action_js"),
        
        # srcdoc / iframe vectors
        (r"\bsrcdoc\s*=", 17, "srcdoc_attr"),
        (r"\biframe[^>]*srcdoc", 18, "iframe_srcdoc"),
        
        # Template / SST injection
        (r"\{\{.*?\}\}", 10, "template_injection"),
        (r"<\s*%.*?%\s*>", 10, "server_tag"),
        
        # Meta refresh
        (r"<\s*meta[^>]*http-equiv\s*=\s*[\"']?refresh", 15, "meta_refresh"),
        (r"<\s*meta[^>]*content\s*=\s*[\"'][^\"']*javascript", 18, "meta_js"),
        
        # Context-breaking
        (r"[\"']\s*>\s*<\s*\w+", 17, "context_break"),
        (r"--\s*>|<!--", 12, "html_comment_break"),
        
        # Obfuscation markers
        (r"\\u[0-9a-fA-F]{4}", 8, "unicode_escape"),
        (r"\\x[0-9a-fA-F]{2}", 8, "hex_escape"),
        (r"/\*.*?\*/", 6, "css_comment_break"),
        (r"&#x?[0-9a-fA-F]+;?", 6, "html_entity_encoded"),
        
        # Character escapes
        (r"&\w+;", 4, "html_entity"),
        
        # Double angle bracket obfuscation
        (r"<<\s*\w", 12, "double_angle"),
        
        # Null byte bypass
        (r"java\x00script", 20, "null_byte_js"),
        (r"on\w+\x00\s*=", 18, "null_byte_event"),
        
        # Uncommon but dangerous
        (r"\bwith\s*\(", 10, "with_statement"),
        (r"\bfunction\s*\*", 8, "generator_function"),

        # Optional chaining invocation (alert?.() / alert?.document?.cookie)
        (r"\b(?:alert|prompt|confirm|eval)\s*\?\.", 20, "optional_chain_call"),
        (r"\bdocument\s*\?\.\s*(?:cookie|domain|location|write)", 18, "optional_chain_dom"),
        (r"\bwindow\s*\?\.", 16, "optional_chain_window"),

        # Indirect invocation: (alert)(1), (confirm)(1), (eval)(...)
        (r"\((?:alert|prompt|confirm|eval)\)\s*[\(`(]", 20, "indirect_invoke_paren"),

        # Bracket notation DOM access: document["cookie"], window["eval"]
        (r"\b(?:document|window)\s*\[\s*[\"'](?:cookie|domain|location|write|eval|body|head)[\"']", 18, "bracket_dom_access"),

        # String concatenation to hide function name: 'ale'+'rt', 'fe'+'tch'
        (r"'(?:ale|pro|con|ev|fe)'[+\s]*\+[+\s]*'(?:rt|mpt|firm|al|tch)'\s*\(", 22, "string_concat_func"),
        (r"\"(?:ale|pro|con|ev|fe)\"[+\s]*\+[+\s]*\"(?:rt|mpt|firm|al|tch)\"\s*\(", 22, "string_concat_func_dq"),
        # Generic: setInterval/setTimeout with concatenated JS string
        (r"\b(?:setInterval|setTimeout)\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*['\"]", 18, "interval_concat"),

        # Prototype pollution + constructor XSS (__proto__[v-if]=...)
        (r"__proto__\s*\[", 20, "prototype_pollution"),
        (r"constructor\s*\(\s*['\"](?:alert|prompt|confirm|eval|fetch)", 22, "constructor_exec"),
        (r"_c\.constructor\s*\(", 20, "vue_constructor"),

        # Tag-breaking inside attributes (<x> inserted mid-word to bypass filters)
        (r"(?:on\w+|href|src)=(?:[^>]*<\w>[^>]*)", 18, "tag_break_attr"),

        # SVG onload/onmouseover without explicit tag scanner catching it
        (r"<svg[^>]*/\s*on\w+\s*=", 20, "svg_slash_event"),

        # Backtick template literal as function argument: prompt\`1\`, alert\`1\`
        (r"\b(?:alert|prompt|confirm|eval)\s*`", 20, "template_literal_call"),
    ]

    def __init__(self, threshold: int = 20):
        self.threshold = threshold
        self._compiled = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), s, n) for p, s, n in self.RULES
        ]

    def get_score(self, raw: str) -> tuple[int, list[str]]:
        if not raw:
            return 0, []

        # Strip null bytes before normalization
        cleaned = raw.replace("\x00", "").replace("\u0000", "")
        s = recursive_normalize(cleaned)

        total = 0
        triggered: list[str] = []

        for compiled_re, base_score, name in self._compiled:
            matches = compiled_re.findall(s)
            if matches:
                # Increased bonus for multiple matches (more aggressive)
                match_bonus = (len(matches) - 1) * 3
                total += base_score + match_bonus
                triggered.append(name)

        # --- Enhanced Combo Bonuses ---
        
        # Script tag with execution functions (very dangerous)
        if "script_open_tag" in triggered or "script_full" in triggered:
            if any(r in triggered for r in ("eval_call", "dialog_call", "base64_decode", "dom_sink_html", "dom_sink_write")):
                total += 25
                triggered.append("combo_script_exec")

        # DOM sink with HTML content (HTML injection via JS)
        if any(r in triggered for r in ("dom_sink_html", "dom_sink_write")):
            if re.search(r"<\w", s):
                total += 18
                triggered.append("combo_dom_html")

        # Event handler on element (very common XSS)
        if any(r in triggered for r in ("event_handler_tag", "event_handler_catch_all")) and re.search(r"<\s*\w+", s):
            total += 15
            triggered.append("combo_event_element")

        # Bare event handler with execution
        if "bare_event_handler" in triggered and any(
            r in triggered for r in ("dialog_call", "eval_call", "func_call_apply", "indirect_invoke", "window_location")
        ):
            total += 15
            triggered.append("combo_bare_event_exec")

        # Protocol-based injection with tag/event
        if any(r in triggered for r in ("js_protocol", "data_html_uri", "vbscript_protocol")):
            if any(r in triggered for r in ("event_handler_tag", "event_handler_catch_all", "media_js_src", "img_js_src_attr", "embed_src")):
                total += 12
                triggered.append("combo_protocol_handler")

        # Multiple obfuscation techniques
        obfus = {"unicode_escape", "hex_escape", "html_entity_encoded", "base64_decode", "null_byte_js", "null_byte_event"}
        if len(obfus & set(triggered)) >= 2:
            total += 15
            triggered.append("combo_multi_obfuscation")

        # SVG-based attack (SVG is powerful attack vector)
        if any(r in triggered for r in ("svg_event", "svg_tag", "svg_animate", "embed_tag")):
            if any(r in triggered for r in ("event_handler_tag", "event_handler_catch_all", "bare_event_handler")):
                total += 15
                triggered.append("combo_svg_attack")

        # Quote imbalance (injection indicator)
        sq, dq = s.count("'"), s.count('"')
        if sq % 2 != 0 or dq % 2 != 0:
            total += 7
            triggered.append("unbalanced_quotes")

        # Multiple angle brackets or context breaks (HTML escape bypass)
        if s.count("<") >= 2 or s.count(">") >= 2:
            if any(r in triggered for r in ("context_break", "html_comment_break")):
                total += 10
                triggered.append("combo_context_escape")

        return total, triggered

    def is_xss(self, raw: str, threshold: int | None = None) -> bool:
        score, _ = self.get_score(raw)
        return score >= (threshold if threshold is not None else self.threshold)

    def analyze(self, raw: str, threshold: int | None = None) -> DetectionResult:
        score, triggered = self.get_score(raw)
        limit = threshold if threshold is not None else self.threshold
        return DetectionResult(
            is_xss=score >= limit,
            score=score,
            triggered_rules=triggered,
        )