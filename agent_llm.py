import json
import os
import re

from knowledge_base import retrieve as retrieve_kb

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

try:
    from groq import Groq
except ImportError:
    Groq = None


ALLOWED_ACTIONS = {"FREEZE_ACCOUNT", "BLOCK_IP", "STEP_UP_AUTH"}
REQUIRED_KEYS = ("tactics", "tactic_id", "explanation", "action", "target_value", "kb_source")

SYSTEM_PROMPT = """
You are the LLM brain for a real-time banking Security Operations Center.
You will receive threat scores, a context tag, a raw JSON transaction event, and a
"knowledge_base_entries" list retrieved from our internal MITRE ATT&CK + SOP reference.

You MUST base "tactics" and "tactic_id" on the provided knowledge_base_entries ONLY.
Do not invent or recall a technique ID from your own memory. If knowledge_base_entries
is empty, set "tactics" to "N/A" and "tactic_id" to "N/A".

Output ONLY a valid JSON object. Do not include markdown, comments, prose, or code fences.
The JSON object must contain exactly these keys:
"tactics": the technique_name from the matching knowledge_base_entries entry.
"tactic_id": the exact technique_id string from that same entry (e.g., T1078, T1020).
"explanation": A natural 1-sentence executive summary that includes the key scores, compares their relative strength, and explains why the selected action follows from that comparison.
"action": Must be one of "FREEZE_ACCOUNT", "BLOCK_IP", or "STEP_UP_AUTH".
"target_value": The exact src_ip or user_id/user value to apply the action to.
"kb_source": copy the "sop" field from the knowledge_base_entries entry you used, verbatim.

Prefer BLOCK_IP when the cyber or quantum score is the dominant high signal.
Prefer FREEZE_ACCOUNT when the fraud score is the dominant high signal.
Prefer STEP_UP_AUTH when the signal is concerning but account freeze or IP block is too aggressive.
Write like a SOC analyst briefing an executive: concise, natural, and comparative.
""".strip()


def _api_key():
    if load_dotenv:
        load_dotenv()
    return os.getenv("GROQ_API_KEY") or os.getenv("GROQ_API")


def _extract_json(text):
    text = text.strip()
    # Remove markdown code fences if the LLM ignores instructions
    text = re.sub(r"^```(json)?", "", text)
    text = re.sub(r"```$", "", text).strip()
    return text


def _coerce_action(action):
    action = str(action).strip().upper()
    if action not in ALLOWED_ACTIONS:
        return "STEP_UP_AUTH"
    return action


def _score_band(score):
    score = float(score or 0)
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "moderate"
    if score >= 30:
        return "elevated"
    return "low"


def _natural_explanation(payload, tag, kb_entry):
    fraud = float(payload.get("fraud_score") or 0)
    cyber = float(payload.get("cyber_score") or 0)
    quantum = float(payload.get("quantum_score") or 0)
    scores = [
        ("fraud", fraud),
        ("cyber", cyber),
        ("quantum", quantum),
    ]
    dominant_name, dominant_score = max(scores, key=lambda item: item[1])
    supporting = [item for item in scores if item[0] != dominant_name and item[1] >= 70]
    moderate = [item for item in scores if item[0] != dominant_name and 50 <= item[1] < 70]

    if supporting:
        support_text = " and is reinforced by " + " and ".join(
            f"{name} at {score:.2f}" for name, score in supporting
        )
    elif moderate:
        support_text = ", with " + " and ".join(
            f"{name} still {_score_band(score)} at {score:.2f}" for name, score in moderate
        )
    else:
        support_text = ", while the other domains remain below the high-risk threshold"

    if supporting and moderate:
        if len(moderate) == 1:
            name, score = moderate[0]
            support_text += f", while {name} remains {_score_band(score)} at {score:.2f}"
        else:
            support_text += ", while " + " and ".join(
                f"{name} remains {_score_band(score)} at {score:.2f}"
                for name, score in moderate
            )

    tactic = kb_entry["technique_name"] if kb_entry else "the mapped threat pattern"
    return (
        f"{tag} aligns with {tactic}: the {dominant_name} signal is "
        f"{_score_band(dominant_score)} at {dominant_score:.2f}{support_text}, "
        f"making this more credible than a single-model anomaly."
    )


def fallback_response(payload, raw_event):
    """Fallback logic if Groq API fails or isn't configured."""
    tag = payload.get("Context_Tag", "")
    fraud = payload.get("fraud_score", 0)
    cyber = payload.get("cyber_score", 0)
    quantum = payload.get("quantum_score", 0)

    kb_entries = retrieve_kb(tag)
    kb_entry = kb_entries[0] if kb_entries else None

    if "QUANTUM" in tag or quantum > 80:
        action = "BLOCK_IP"
        target = raw_event.get("src_ip", "UNKNOWN_IP")
    elif "CYBER" in tag or cyber > 80:
        action = "BLOCK_IP"
        target = raw_event.get("src_ip", "UNKNOWN_IP")
    else:
        action = "FREEZE_ACCOUNT"
        target = raw_event.get("user") or raw_event.get("user_id") or "UNKNOWN_USER"

    tactics = kb_entry["technique_name"] if kb_entry else "N/A"
    tactic_id = kb_entry["technique_id"] if kb_entry else "N/A"
    kb_source = kb_entry["sop"] if kb_entry else "Handle per standard triage procedure."

    return {
        "tactics": tactics,
        "tactic_id": tactic_id,
        "explanation": _natural_explanation(payload, tag, kb_entry),
        "action": action,
        "target_value": str(target),
        "kb_source": kb_source,
    }


def analyze_threat(payload, raw_event):
    """
    Calls Groq for a constrained JSON decision. Any API, auth, network,
    parsing, or validation failure falls back to a deterministic mock JSON.
    """
    key = _api_key()
    if not key or Groq is None:
        return fallback_response(payload, raw_event)

    user_prompt = json.dumps(
        {
            "threat_payload": payload,
            "raw_transaction_event": raw_event,
            "knowledge_base_entries": retrieve_kb(payload.get("Context_Tag", "")),
        },
        default=str,
    )

    try:
        client = Groq(api_key=key)
        completion = client.chat.completions.create(
            model='llama-3.1-8b-instant',
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0,
            max_tokens=220,
            response_format={"type": "json_object"},
        )
        content = completion.choices[0].message.content
        return _coerce_action_and_validate(content, payload, raw_event)
    except Exception as e:
        print(f"Groq API Error: {e}")
        return fallback_response(payload, raw_event)

def _coerce_action_and_validate(content, payload, raw_event):
    content = _extract_json(content)
    parsed = json.loads(content)
    tag = payload.get("Context_Tag", "")
    kb_entries = retrieve_kb(tag)
    kb_entry = kb_entries[0] if kb_entries else None

    parsed["action"] = _coerce_action(parsed.get("action"))
    parsed.setdefault("tactics", kb_entry["technique_name"] if kb_entry else "N/A")
    parsed.setdefault("tactic_id", kb_entry["technique_id"] if kb_entry else "N/A")
    parsed.setdefault(
        "kb_source",
        kb_entry["sop"] if kb_entry else "Handle per standard triage procedure.",
    )

    explanation = str(parsed.get("explanation") or "").strip()
    if not explanation or "detected with fraud=" in explanation.lower():
        parsed["explanation"] = _natural_explanation(payload, tag, kb_entry)

    return {key: parsed.get(key) for key in REQUIRED_KEYS}

AGENTIC_SYSTEM_PROMPT = """
You are the agentic decision-maker for a real-time banking Security Operations Center.
You have two tools available:

1. lookup_user_history(user): fetch this user's recent event history before deciding,
   if the current signal alone is ambiguous (e.g. MULTIPLE_MILD_SIGNALS, LOW_RISK_WATCH).
2. execute_action(action, target_value): actually perform a containment action. Only
   call this ONCE you have decided. action must be one of FREEZE_ACCOUNT, BLOCK_IP,
   STEP_UP_AUTH. This is the ONLY way an action is actually carried out -- describing
   an action in text does not execute it.

You will receive threat scores, a context tag, a raw JSON event, and knowledge_base_entries
retrieved from our internal MITRE ATT&CK + SOP reference. Base "tactics"/"tactic_id" ONLY on
knowledge_base_entries -- never invent a technique ID from memory.

Process: optionally call lookup_user_history if you need more context, then call
execute_action to perform your decision, then respond with ONLY a final JSON object
(no markdown, no prose) with exactly these keys: tactics, tactic_id, explanation,
action, target_value, kb_source. This final JSON must match what you passed to
execute_action.

The explanation must be natural analyst language: include the relevant scores, compare
which model is dominant versus supporting or weaker signals, and explain why the action
is justified. Avoid robotic templates like "detected with fraud=X, cyber=Y".
""".strip()

AGENTIC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup_user_history",
            "description": "Fetch this user's recent event history for extra context before deciding.",
            "parameters": {
                "type": "object",
                "properties": {"user": {"type": "string"}},
                "required": ["user"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_action",
            "description": "Actually perform a containment action. This is the only way an action executes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": list(ALLOWED_ACTIONS)},
                    "target_value": {"type": "string"},
                },
                "required": ["action", "target_value"],
            },
        },
    },
]


def _tool_lookup_user_history(args, events, max_events=5):
    user = args.get("user")
    matches = [e for e in events if (e.get("user") or e.get("user_id")) == user]
    return json.dumps(matches[-max_events:], default=str)


def _tool_execute_action(args, action_executor):
    action = _coerce_action(args.get("action"))
    target = args.get("target_value")
    if action_executor:
        action_executor(action, target)  # real side effect, e.g. block IP / freeze account
    return json.dumps({"executed": True, "action": action, "target_value": target})


def analyze_threat_agentic(payload, raw_event, events, action_executor=None, client=None, max_turns=4):
    """
    Genuine tool-calling agentic loop. Falls back to the deterministic
    fallback_response() if no API key/client, or on any error -- same
    safety guarantee as analyze_threat().
    """
    key = _api_key()
    if client is None:
        if not key or Groq is None:
            return fallback_response(payload, raw_event)
        client = Groq(api_key=key)

    messages = [
        {"role": "system", "content": AGENTIC_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps({
            "threat_payload": payload,
            "raw_transaction_event": raw_event,
            "knowledge_base_entries": retrieve_kb(payload.get("Context_Tag", "")),
        }, default=str)},
    ]

    try:
        for _ in range(max_turns):
            completion = client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=messages,
                tools=AGENTIC_TOOLS,
                tool_choice="auto",
                temperature=0,
                max_tokens=400,
            )
            msg = completion.choices[0].message
            tool_calls = getattr(msg, "tool_calls", None)

            if not tool_calls:
                return _coerce_action_and_validate(msg.content, payload, raw_event)

            messages.append({"role": "assistant", "content": msg.content, "tool_calls": tool_calls})
            for tc in tool_calls:
                fn_name = tc.function.name
                fn_args = json.loads(tc.function.arguments)
                if fn_name == "lookup_user_history":
                    result = _tool_lookup_user_history(fn_args, events)
                elif fn_name == "execute_action":
                    result = _tool_execute_action(fn_args, action_executor)
                else:
                    result = json.dumps({"error": f"unknown tool {fn_name}"})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})

        # ran out of turns without a final answer -- safe fallback, no silent failure
        return fallback_response(payload, raw_event)

    except Exception as e:
        print(f"Agentic loop error: {e}")
        return fallback_response(payload, raw_event)
