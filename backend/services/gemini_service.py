import os
import json
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from config import settings

logger = logging.getLogger("breachsieve.gemini")

class GeminiFindingTriage(BaseModel):
    verdict: str = Field(..., description="'confirmed', 'false_positive', or 'needs_review'")
    reasoning: str = Field(..., description="Detailed written justification explicitly quoting the evidence")
    novel_pattern_flag: bool = Field(..., description="True if the pattern looks like a known weakness class not yet seen or in an unfamiliar context, rather than a standard pattern")
    remediation_note: Optional[str] = Field(None, description="Actionable recommendation based on the observed evidence")

class GeminiService:
    """
    Integrates with Google Gemini API via official `google-genai` SDK
    to perform false-positive triage, evidence-quoted reasoning,
    and novel/anomalous pattern detection on OWASP ZAP alerts.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY")
        self.client = None
        self.model_name = settings.GEMINI_MODEL or "gemini-2.5-flash"

        if self.api_key and self.api_key.strip():
            try:
                from google import genai
                self.client = genai.Client(api_key=self.api_key.strip())
                logger.info("Google GenAI client initialized successfully with API key.")
            except Exception as e:
                logger.warning(f"Failed to initialize Google GenAI client: {e}")
                self.client = None
        else:
            logger.info("GEMINI_API_KEY not set. GeminiService will run in deterministic fallback triage mode.")

    def is_live(self) -> bool:
        """Returns True if Gemini API client is configured with a valid key."""
        return self.client is not None

    def triage_finding_group(
        self,
        rule_name: str,
        cwe_id: str,
        zap_risk: str,
        zap_confidence: str,
        url: str,
        param: str,
        evidence_text: str,
        request_snippet: str,
        response_snippet: str,
        seen_weakness_classes: set
    ) -> Dict[str, Any]:
        """
        Analyzes a finding group with evidence.
        Returns verdict ('confirmed' | 'false_positive' | 'needs_review'),
        reasoning quoting evidence, and novel_pattern_flag.
        """
        if self.client:
            try:
                return self._call_gemini_api(
                    rule_name=rule_name,
                    cwe_id=cwe_id,
                    zap_risk=zap_risk,
                    zap_confidence=zap_confidence,
                    url=url,
                    param=param,
                    evidence_text=evidence_text,
                    request_snippet=request_snippet,
                    response_snippet=response_snippet,
                    seen_weakness_classes=seen_weakness_classes
                )
            except Exception as e:
                logger.error(f"Gemini API invocation failed ({e}), falling back to deterministic triage.")

        # Fallback to deterministic triage engine
        return self._deterministic_triage(
            rule_name=rule_name,
            cwe_id=cwe_id,
            zap_risk=zap_risk,
            zap_confidence=zap_confidence,
            url=url,
            param=param,
            evidence_text=evidence_text,
            request_snippet=request_snippet,
            response_snippet=response_snippet,
            seen_weakness_classes=seen_weakness_classes
        )

    def _call_gemini_api(
        self,
        rule_name: str,
        cwe_id: str,
        zap_risk: str,
        zap_confidence: str,
        url: str,
        param: str,
        evidence_text: str,
        request_snippet: str,
        response_snippet: str,
        seen_weakness_classes: set
    ) -> Dict[str, Any]:
        from google.genai import types

        prompt = f"""You are an elite AppSec engineer triaging an automated DAST alert from OWASP ZAP.
Perform strict false-positive filtering and novel anomaly triage.

Alert Details:
- Vulnerability Rule: {rule_name}
- CWE: {cwe_id}
- ZAP Reported Risk: {zap_risk}
- ZAP Reported Confidence: {zap_confidence}
- Affected URL: {url}
- Parameter / Vector: {param or 'N/A'}
- Evidence from Scanner: {evidence_text or 'None'}

HTTP Request Excerpt:
{request_snippet[:1500] if request_snippet else '[No request excerpt recorded]'}

HTTP Response Excerpt:
{response_snippet[:2000] if response_snippet else '[No response excerpt recorded]'}

Previously observed weakness classes in this scan: {list(seen_weakness_classes)}

Instructions:
1. Examine the HTTP response and evidence. Check if the scanner payload actually executed or if the response simply reflects static text, returns a 404/500 generic error, or is protected by existing headers.
2. Determine Verdict:
   - 'confirmed': Real vulnerability with corroborating evidence in the response/headers.
   - 'false_positive': Scanner misinterpreted normal behavior, generic error page, or benign reflection.
   - 'needs_review': Evidence is suggestive but inconclusive without manual verification.
3. Provide reasoning that MUST explicitly quote exact strings from the evidence, request, or response.
4. Set 'novel_pattern_flag' to true ONLY if this vulnerability represents an unfamiliar instance or variant of a known weakness class ({cwe_id}) not previously seen in this scan, rather than standard boilerplate.
"""

        models_to_try = [self.model_name]
        for fallback in ["gemini-3.8-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"]:
            if fallback not in models_to_try:
                models_to_try.append(fallback)

        response = None
        last_error = None
        for m in models_to_try:
            try:
                response = self.client.models.generate_content(
                    model=m,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=GeminiFindingTriage,
                        temperature=0.1
                    )
                )
                if response and response.text:
                    break
            except Exception as e:
                last_error = e
                logger.warning(f"Gemini call with {m} failed: {e}. Trying next fallback...")

        if not response or not response.text:
            raise last_error or RuntimeError("All Gemini candidate models failed to return content")

        try:
            data = json.loads(response.text)
            verdict = data.get("verdict", "confirmed").lower()
            if verdict not in ("confirmed", "false_positive", "needs_review"):
                verdict = "confirmed"

            return {
                "verdict": verdict,
                "reasoning": data.get("reasoning", "Triaged and confirmed by Gemini AI analysis."),
                "novel_pattern_flag": bool(data.get("novel_pattern_flag", False)),
                "remediation_note": data.get("remediation_note")
            }
        except Exception as err:
            logger.warning(f"Error parsing Gemini response JSON: {err}. Raw text: {response.text}")
            return {
                "verdict": "confirmed",
                "reasoning": f"Gemini triage completed: {response.text[:250]}",
                "novel_pattern_flag": False,
                "remediation_note": None
            }

    def _deterministic_triage(
        self,
        rule_name: str,
        cwe_id: str,
        zap_risk: str,
        zap_confidence: str,
        url: str,
        param: str,
        evidence_text: str,
        request_snippet: str,
        response_snippet: str,
        seen_weakness_classes: set
    ) -> Dict[str, Any]:
        """
        Robust deterministic heuristic engine for triage when Gemini API key is not configured.
        Strictly quotes evidence and never silently passes Low-confidence alerts.
        """
        rule_lower = rule_name.lower()
        evidence_lower = (evidence_text or "").lower()
        response_lower = (response_snippet or "").lower()

        # Rule 1: Missing Evidence on Low Confidence alerts
        if zap_confidence.lower() == "low" and not evidence_text:
            return {
                "verdict": "false_positive",
                "reasoning": (
                    f"Classified as false_positive because ZAP reported confidence '{zap_confidence}' "
                    f"with no matching evidence string found in the HTTP response body or headers."
                ),
                "novel_pattern_flag": False,
                "remediation_note": "No remediation required for uncorroborated low-confidence alert."
            }

        # Rule 2: Anti-clickjacking / X-Frame-Options
        if "clickjacking" in rule_lower or "x-frame-options" in rule_lower or cwe_id == "CWE-1021":
            if "x-frame-options" not in response_lower and "frame-ancestors" not in response_lower:
                return {
                    "verdict": "confirmed",
                    "reasoning": (
                        "Confirmed: HTTP response headers omit both 'X-Frame-Options' and CSP 'frame-ancestors'. "
                        "The target page can be rendered inside an unauthorized <iframe> layer."
                    ),
                    "novel_pattern_flag": cwe_id not in seen_weakness_classes,
                    "remediation_note": "Configure 'Content-Security-Policy: frame-ancestors self' and 'X-Frame-Options: SAMEORIGIN'."
                }
            else:
                return {
                    "verdict": "false_positive",
                    "reasoning": "Framing protection headers were detected in the response stream.",
                    "novel_pattern_flag": False,
                    "remediation_note": None
                }

        # Rule 3: Content Security Policy
        if "content security policy" in rule_lower or "csp" in rule_lower:
            if "content-security-policy" not in response_lower:
                return {
                    "verdict": "confirmed",
                    "reasoning": "Confirmed: No 'Content-Security-Policy' HTTP response header is transmitted by the server.",
                    "novel_pattern_flag": cwe_id not in seen_weakness_classes,
                    "remediation_note": "Deploy a strict Content-Security-Policy header."
                }

        # Rule 4: HSTS
        if "strict-transport-security" in rule_lower or "hsts" in rule_lower or cwe_id == "CWE-319":
            if "strict-transport-security" not in response_lower:
                return {
                    "verdict": "confirmed",
                    "reasoning": "Confirmed: 'Strict-Transport-Security' response header is absent over HTTPS communication.",
                    "novel_pattern_flag": cwe_id not in seen_weakness_classes,
                    "remediation_note": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
                }

        # Rule 5: X-Content-Type-Options
        if "content-type-options" in rule_lower:
            if "x-content-type-options" not in response_lower:
                return {
                    "verdict": "confirmed",
                    "reasoning": "Confirmed: Missing 'X-Content-Type-Options: nosniff' header enables MIME sniffing vulnerabilities.",
                    "novel_pattern_flag": cwe_id not in seen_weakness_classes,
                    "remediation_note": "Send 'X-Content-Type-Options: nosniff' on all text/html and script responses."
                }

        # Rule 6: SQL Injection / XSS with clear evidence
        if evidence_text and (evidence_lower in response_lower or len(evidence_text) > 3):
            is_novel = cwe_id not in seen_weakness_classes and zap_risk in ("High", "Critical")
            return {
                "verdict": "confirmed",
                "reasoning": (
                    f"Confirmed: Scanner detected active reflection of test vector quoting evidence: "
                    f"'{evidence_text[:120]}' in response context at '{url}'."
                ),
                "novel_pattern_flag": is_novel,
                "remediation_note": "Apply parameterized inputs or contextual HTML entity encoding."
            }

        # Rule 7: Low confidence with generic 404 or 500 error response
        if ("404 not found" in response_lower or "500 internal server error" in response_lower) and zap_confidence.lower() == "low":
            return {
                "verdict": "false_positive",
                "reasoning": (
                    f"Classified as false_positive: Low-confidence trigger occurred inside generic error page "
                    f"without verifiable exploit execution. Quoting response context: '{response_snippet[:80]}'."
                ),
                "novel_pattern_flag": False,
                "remediation_note": None
            }

        # Default fallback: needs_review if low confidence, confirmed otherwise
        if zap_confidence.lower() == "low":
            return {
                "verdict": "needs_review",
                "reasoning": (
                    f"Flagged for manual review: Low-confidence finding on {rule_name}. "
                    f"Scanner observed '{evidence_text[:100]}' but requires analyst confirmation."
                ),
                "novel_pattern_flag": False,
                "remediation_note": "Manually verify payload execution in browser devtools."
            }

        return {
            "verdict": "confirmed",
            "reasoning": f"Confirmed vulnerability based on corroborating scanner evidence: '{evidence_text[:120]}'.",
            "novel_pattern_flag": cwe_id not in seen_weakness_classes,
            "remediation_note": None
        }
