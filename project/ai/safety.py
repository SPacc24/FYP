import re


SAFE_REFUSAL = (
    "I can help explain the finding, MITRE ATT&CK mapping, risk, remediation, "
    "or safe validation goals, but I cannot provide exploit commands, payloads, "
    "credential theft steps, bypass instructions, or intrusion walkthroughs."
)


UNSAFE_REQUEST_PATTERNS = [
    r"\b(reverse shell|bind shell|web shell)\b",
    r"\b(payload|shellcode)\b",
    r"\b(mimikatz|hashdump|dump passwords?|steal credentials?)\b",
    r"\b(bypass|evade)\b.*\b(edr|av|antivirus|defen[sc]e|detection)\b",
    r"\b(disable|turn off)\b.*\b(edr|av|antivirus|firewall|defender)\b",
    r"\b(exploit|hack|break into|compromise)\b.*\b(command|step by step|payload|script|how do i|how to)\b",
    r"\b(msfconsole|meterpreter|cobalt strike|empire)\b",
]

UNSAFE_RESPONSE_PATTERNS = [
    r"\bmsfconsole\b",
    r"\bmeterpreter\b",
    r"\bmimikatz\b",
    r"\bnc\s+-[a-z]*e\b",
    r"\bpowershell\b.*\b(encodedcommand|downloadstring|iex)\b",
    r"\bcurl\b.*\|\s*(sh|bash|powershell)\b",
]


def contains_unsafe_content(text: str, patterns: list[str]) -> bool:
    value = str(text or "").lower()
    return any(re.search(pattern, value, flags=re.IGNORECASE) for pattern in patterns)


def is_unsafe_user_request(message: str) -> bool:
    return contains_unsafe_content(message, UNSAFE_REQUEST_PATTERNS)


def sanitize_llm_reply(reply: str) -> str:
    """
    Keep chat output in the decision-support lane if the local model drifts.
    """
    if contains_unsafe_content(reply, UNSAFE_RESPONSE_PATTERNS):
        return SAFE_REFUSAL

    return str(reply or "").strip() or "No reply returned."
