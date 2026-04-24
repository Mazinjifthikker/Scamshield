from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import google.generativeai as genai
import os, json, re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="ScamShield API v2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)
    model = genai.GenerativeModel("gemini-flash-latest")
else:
    model = None

# -----------------------------------------
class AnalyseRequest(BaseModel):
    message: str
    message_type: str

class PhoneRequest(BaseModel):
    phone_number: str


# ── PROMPTS ─────────────────────────────────────────
SCAM_PROMPT = """
You are ScamShield, a Malaysian financial fraud detection AI. Analyse the message below for scam indicators.

You know these Malaysian scam patterns:
- Maybank2u, CIMB Clicks, RHB, Public Bank, BSN phishing
- PDRM, LHDN, JPJ, BNM, MySejahtera impersonation (Macau Scam)
- Shopee, Lazada, TikTok Shop prize/lucky draw scams
- Pos Malaysia, J&T Express, DHL parcel delivery scams
- Fake job offers (kerja dari rumah, modal kecil)
- Investment scams (crypto, Telegram group signals)
- Loan shark / Ah Long messages
- EPF/KWSP, SOCSO withdrawal scams
- Government aid (Bantuan Rakyat) phishing

Respond ONLY with valid JSON, no markdown:
{
  "risk_level": "LOW"|"MEDIUM"|"HIGH",
  "risk_score": 0-100,
  "verdict": "one sentence",
  "red_flags": ["flag1","flag2"],
  "explanation": "2-3 sentence analysis",
  "advice": ["action1","action2","action3"],
  "scam_type": "specific type or Not a scam"
}
"""

PHONE_PROMPT = """
You are ScamShield, a Malaysian phone number risk analyser. Analyse if this phone number is likely used by scammers.

Consider:
- Malaysian numbers: +60 or 0 prefix, valid area codes (03 KL, 04 Penang, 05 Perak, 07 Johor, 08 Sabah/Sarawak, 09 Kelantan/Terengganu)
- Mobile: 011, 012, 013, 014, 016, 017, 018, 019
- International numbers claiming to be Malaysian authorities = HIGH RISK
- Numbers from +44 (UK), +1 (US/Canada), +62 (Indonesia) impersonating local = HIGH RISK
- Private/withheld numbers for financial requests = MEDIUM RISK
- Known bank hotlines (1300-88-6688 Maybank, 1300-880-900 CIMB) = LOW RISK
- NSRC hotline 997 = SAFE

Respond ONLY with valid JSON, no markdown:
{
  "risk_level": "LOW"|"MEDIUM"|"HIGH",
  "risk_score": 0-100,
  "verdict": "one sentence",
  "explanation": "analysis of this number",
  "advice": ["action1","action2"]
}
"""


# ── KNOWLEDGE BASE / RULES ──────────────────────────
SCAM_PATTERNS = [
    {
        "name": "Bank phishing",
        "keywords": ["maybank", "maybank2u", "cimb", "public bank", "rhb", "bsn", "secure", "verify", "login"],
        "risk_boost": 28,
        "flags": ["Mentions bank account verification", "Likely phishing theme"]
    },
    {
        "name": "Authority impersonation",
        "keywords": ["pdrm", "lhdn", "jpj", "bnm", "bank negara", "mahkamah", "polis", "court", "saman"],
        "risk_boost": 30,
        "flags": ["Pretends to be an authority", "Pressure through legal or official language"]
    },
    {
        "name": "Parcel delivery scam",
        "keywords": ["parcel", "bungkusan", "delivery", "pos malaysia", "poslaju", "j&t", "dhl", "alamat"],
        "risk_boost": 20,
        "flags": ["Delivery or parcel pretext detected"]
    },
    {
        "name": "Prize / lucky draw scam",
        "keywords": ["tahniah", "winner", "prize", "hadiah", "lucky draw", "menang", "claim now"],
        "risk_boost": 22,
        "flags": ["Unexpected prize or winnings claim"]
    },
    {
        "name": "Fake job offer",
        "keywords": ["kerja", "work from home", "part time", "modal kecil", "gaji", "komisen", "job offer"],
        "risk_boost": 22,
        "flags": ["Suspicious job offer pattern"]
    },
    {
        "name": "Investment / crypto scam",
        "keywords": ["investment", "crypto", "telegram group", "profit", "returns", "forex", "signal"],
        "risk_boost": 26,
        "flags": ["High-return investment language detected"]
    },
    {
        "name": "Loan shark / Ah Long",
        "keywords": ["loan", "pinjaman", "ah long", "approval", "fast cash", "blacklist"],
        "risk_boost": 18,
        "flags": ["High-risk lending language detected"]
    },
]

AUTHORITY_TERMS = [
    "pdrm", "lhdn", "jpj", "bnm", "bank negara", "mahkamah", "polis", "court", "kwsp", "socso", "epf"
]

URGENCY_TERMS = [
    "urgent", "immediately", "segera", "24 jam", "today", "within", "final warning", "last chance",
    "akaun akan ditutup", "suspended", "digantung", "cepat", "sekarang"
]

MONEY_TERMS = [
    "rm", "ringgit", "cash", "bayar", "payment", "transfer", "deposit", "fee", "modal", "duit", "withdrawal"
]


# ── HELPERS ─────────────────────────────────────────
def ensure_model():
    if model is None:
        raise HTTPException(500, "GOOGLE_API_KEY is missing. Add it to your .env file.")

def extract_json_object(text: str) -> dict:
    cleaned = re.sub(r"```json|```", "", text, flags=re.IGNORECASE).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    raise json.JSONDecodeError("Could not parse JSON", cleaned, 0)


def analyse_message_signals(message: str) -> dict:
    lower = message.lower()
    links = re.findall(r'https?://\S+|www\.\S+', message, flags=re.IGNORECASE)
    authorities = [term for term in AUTHORITY_TERMS if term in lower]
    urgency_hits = [term for term in URGENCY_TERMS if term in lower]
    money_hits = [term for term in MONEY_TERMS if term in lower]

    matched_patterns = []
    risk_boost = 0
    rule_flags = []

    for pattern in SCAM_PATTERNS:
        hits = [kw for kw in pattern["keywords"] if kw in lower]
        if hits:
            matched_patterns.append({
                "pattern": pattern["name"],
                "matched_keywords": hits
            })
            risk_boost += pattern["risk_boost"]
            rule_flags.extend(pattern["flags"])

    if links:
        risk_boost += 15
        rule_flags.append("Contains a clickable link")
    if urgency_hits:
        risk_boost += 10
        rule_flags.append("Uses urgency or pressure tactics")
    if authorities:
        risk_boost += 12
        rule_flags.append("References official authority names")
    if money_hits:
        risk_boost += 8
        rule_flags.append("Mentions money, payment, or transfer")

    return {
        "links_found": links,
        "authorities_found": authorities,
        "urgency_terms_found": urgency_hits,
        "money_terms_found": money_hits,
        "matched_patterns": matched_patterns,
        "rule_based_risk_boost": min(risk_boost, 70),
        "rule_flags": list(dict.fromkeys(rule_flags))
    }


def analyze_phone_locally(phone_number: str) -> dict | None:
    raw = phone_number.strip()
    normalized = re.sub(r"[^\d+]", "", raw)
    lowered = raw.lower()

    if raw == "997" or normalized == "997":
        return {
            "risk_level": "LOW",
            "risk_score": 0,
            "verdict": "This is the National Scam Response Centre hotline and is considered safe.",
            "explanation": "997 is Malaysia's National Scam Response Centre hotline, used for scam response and reporting.",
            "advice": ["You can contact 997 quickly if you suspect a scam.", "Do not delay reporting fraudulent bank transfers."]
        }

    known_safe = {
        "1300886688": "Maybank customer line",
        "1300880900": "CIMB customer line",
        "1800882020": "Bank Negara Malaysia line"
    }
    digits_only = re.sub(r"\D", "", raw)
    if digits_only in known_safe:
        return {
            "risk_level": "LOW",
            "risk_score": 10,
            "verdict": f"This number matches a known official hotline: {known_safe[digits_only]}.",
            "explanation": "The number matches a commonly known official service line, so the baseline risk is low.",
            "advice": ["Still verify through the official website before sharing sensitive information.", "Be cautious if the caller asks for OTPs or passwords."]
        }

    if "private" in lowered or "withheld" in lowered or "unknown" in lowered:
        return {
            "risk_level": "MEDIUM",
            "risk_score": 60,
            "verdict": "Private or withheld caller IDs are riskier for financial or urgent requests.",
            "explanation": "Scammers often hide caller IDs to avoid traceability, especially when using fear or payment pressure.",
            "advice": ["Do not share OTPs or banking details.", "Call the official organization back using its public number."]
        }

    if normalized.startswith("+44") or normalized.startswith("+1") or normalized.startswith("+62"):
        return {
            "risk_level": "HIGH",
            "risk_score": 85,
            "verdict": "This foreign number is high-risk if it claims to be a Malaysian bank or authority.",
            "explanation": "International numbers are commonly used in impersonation scams targeting Malaysians, especially when pretending to be local institutions.",
            "advice": ["Do not trust claims of being from a Malaysian authority without verification.", "Hang up and call the official hotline yourself."]
        }

    return None


def clamp_score(value: int) -> int:
    return max(0, min(100, value))


# ── ENDPOINTS ───────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse("<h1>ScamShield API is running</h1><p>Visit <a href='/docs'>/docs</a> to test the API.</p>")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ScamShield API v2",
        "model": "gemini-flash-latest",
        "api_key_loaded": bool(GOOGLE_API_KEY),
        "workflow": "rules + gemini"
    }


@app.post("/analyse")
async def analyse(req: AnalyseRequest):
    ensure_model()
    if not req.message.strip():
        raise HTTPException(400, "Message cannot be empty")

    signals = analyse_message_signals(req.message)

    prompt = f"""{SCAM_PROMPT}

Pre-analysis signals from ScamShield workflow:
{json.dumps(signals, indent=2, ensure_ascii=False)}

Instructions:
- Use the pre-analysis signals as supporting evidence.
- If links, urgency, authority impersonation, or money requests appear together, treat risk as likely elevated.
- Keep the response fully consistent with the message content.
- Respond with valid JSON only.

Message Type: {req.message_type}
Message:
{req.message}
"""

    try:
        resp = model.generate_content(prompt)
        data = extract_json_object(resp.text)

        if "risk_score" in data:
            boosted_score = clamp_score(int(data["risk_score"]) + signals["rule_based_risk_boost"] // 3)
            data["risk_score"] = boosted_score
            if boosted_score >= 75:
                data["risk_level"] = "HIGH"
            elif boosted_score >= 40:
                data["risk_level"] = "MEDIUM"
            else:
                data["risk_level"] = "LOW"

        existing_flags = data.get("red_flags", [])
        merged_flags = list(dict.fromkeys(existing_flags + signals["rule_flags"]))
        data["red_flags"] = merged_flags[:6]

        return {**data, "workflow_signals": signals}
    except json.JSONDecodeError:
        raise HTTPException(500, "Failed to parse AI response")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/check-phone")
async def check_phone(req: PhoneRequest):
    ensure_model()
    if not req.phone_number.strip():
        raise HTTPException(400, "Phone number cannot be empty")

    local_result = analyze_phone_locally(req.phone_number)
    if local_result is not None:
        return local_result

    prompt = f"""{PHONE_PROMPT}

Phone Number to analyse: {req.phone_number}
"""

    try:
        resp = model.generate_content(prompt)
        data = extract_json_object(resp.text)
        if "risk_score" in data:
            data["risk_score"] = clamp_score(int(data["risk_score"]))
        return data
    except json.JSONDecodeError:
        raise HTTPException(500, "Failed to parse AI response")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/news")
async def get_news():
    feeds = [
        "https://news.google.com/rss/search?q=scam+Malaysia&hl=en-MY&gl=MY&ceid=MY:en",
        "https://news.google.com/rss/search?q=penipuan+Malaysia&hl=ms&gl=MY&ceid=MY:ms",
    ]
    articles = []
    seen = set()

    for feed_url in feeds:
        try:
            req = urllib.request.Request(
                feed_url,
                headers={"User-Agent": "Mozilla/5.0 ScamShield/2.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                content = r.read()

            root = ET.fromstring(content)
            channel = root.find("channel")
            if channel is None:
                continue

            for item in channel.findall("item")[:12]:
                title = item.findtext("title", "").strip()
                link = item.findtext("link", "").strip()
                pub = item.findtext("pubDate", "").strip()
                source_el = item.find("{https://news.google.com/rss}source")
                source = source_el.text if source_el is not None else "News"

                title = re.sub(r'\s*-\s*[^-]+$', '', title).strip()

                if title and title not in seen:
                    seen.add(title)
                    try:
                        dt = datetime.strptime(pub, "%a, %d %b %Y %H:%M:%S %Z")
                        pub_fmt = dt.strftime("%d %b %Y")
                    except Exception:
                        pub_fmt = pub[:16] if pub else "Recent"

                    articles.append({
                        "title": title,
                        "link": link,
                        "source": source,
                        "pubDate": pub_fmt
                    })
        except Exception:
            continue

    return articles[:15]
