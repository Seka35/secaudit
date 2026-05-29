"""AI-powered vulnerability analysis using OpenRouter."""
import os
import json
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_KEY = os.getenv("OPENROUTER_KEY", "").strip()
MODEL = os.getenv("MODEL", "deepseek/deepseek-v3").strip()

SYSTEM_PROMPT = """Tu es un expert en sécurité informatique avec plus de 10 ans d'expérience en penetration testing et hacking éthique. Tu as travaillé sur des centaines de missions Red Team et tu connais les techniques d'attaque les plus avancées.

Pour chaque vulnérabilité trouvée dans le rapport, tu dois fournir:

1. **ANALYSE DE LA VULNÉRABILITÉ**
   - Description technique détaillée
   - Composants affected
   - Prérequis pour l'exploitation

2. **ÉTAPES D'EXPLOITATION CONCRÈTES**
   - Commandes exactes à exécuter
   - Outils à utiliser (nmap, burp, sqlmap, metasploit, etc.)
   - Payloads spécifiques
   -一步一步 (step-by-step) commentcompromettre le système

3. **ESCALATION ET POST-EXPLOITATION**
   - Comment escalader les privilèges
   - Comment maintenir l'accès
   - Comment pivoter vers d'autres systèmes
   - Comment exfiltrer les données

4. **IMPACT RÉEL**
   - Damage assessment concret
   - What données can be stolen
   - Business impact

5. **GUIDE DE CORRECTION**
   - Exact steps to fix
   - Configuration changes needed
   - Code fixes with examples
   - Tools to verify the fix

RAPPORTS D'EXPLOITATION - RÈGLES:
- Sois spécifique, pas générique
- Donne les commandes réelles, pas des exemples
- Include les URLs, IPs, et parameters exacts
- Considère le contexte de l'application (tech stack, framework)
- Si plusieurs chemins d'exploitation existent, donne le plus critique

Pour les secrets/API keys exposés:
- Donne les commandes curl/api exactes pour tester la clé
- Montre comment énumérer les ressources accessibles
- Explique comment abuser du service

Pour les XSS:
- Donne le payload exact
- Montre comment steal cookies/sessions
- Comment bypass les filtres éventuels

Pour les SQL injections:
- Payload exact (OR 1=1, UNION SELECT, etc.)
- Comment dump la database
- Comment lire fichiers système si possible

Pour les misconfigurations:
- Exact config à changer
- Outil pour tester la misconfiguration
- Comment exploiter pour accès non autorisé

Format de réponse:
---
## 🔴 [VULNÉRABILITÉ CRITIQUE] Nom
**Target:** URL/IP
**Tech Stack:** ce qui est utilisé

### Exploitation
```
[commandes exactes]
```

### Post-Exploitation
```
[étapes pour aller plus loin]
```

### Correction
```
[fix exact avec code/config]
```
---

CRITICAL: Chaque exploitation DOIT être réaliste, testable, et montrer l'impact concret. Pas de理论知识 - que du pratique."""

USER_PROMPT_TEMPLATE = """Analyse ce rapport de sécurité et fournis des étapes d'exploitation détaillées pour chaque vulnérabilité trouvée.

{report_summary}

Pour chaque vulnérabilité HIGH ou CRITICAL, donne:
1. Les commandes exactes pour exploiter
2. Les outils nécessaires
3. Comment compromettre le système
4. Comment patcher

Si une API key ou secret est exposé, donne les commandes curl/API exactes pour:
- Tester si la clé fonctionne
- Énumérer les ressources accessibles
- Abuser du service

Sois spécifique et technique. Donne des commandes réelles."""


def analyze_with_ai(report_data: dict, target_url: str) -> tuple:
    """Send report to OpenRouter AI for detailed exploitation analysis.
    Returns (success: bool, result: str or error_message)"""
    if not OPENROUTER_KEY:
        return (False, "OPENROUTER_KEY not configured in .env")

    try:
        import requests
    except ImportError:
        return (False, "requests library not installed")

    # Build summary from report
    summary_parts = [f"Target: {target_url}\n"]

    # Extract key findings
    if report_data.get("tech", {}).get("detected"):
        summary_parts.append(f"\n**Technologies détectées:** {', '.join(report_data['tech']['detected'])}")

    if report_data.get("secrets"):
        summary_parts.append(f"\n**Secrets exposés:**")
        for s in report_data["secrets"]:
            summary_parts.append(f"  - {s.get('type')}: {s.get('value_masked', 'N/A')} (Severity: {s.get('severity', 'N/A')})")

    if report_data.get("js_analysis"):
        summary_parts.append(f"\n**Vulnérabilités JS:**")
        for v in report_data.get("js_analysis", [])[:5]:
            summary_parts.append(f"  - {v.get('pattern')}: {v.get('description', 'N/A')}")

    if report_data.get("sensitive_paths"):
        summary_parts.append(f"\n**Fichiers sensibles exposés:**")
        for p in report_data["sensitive_paths"]:
            summary_parts.append(f"  - {p.get('path')} (Status: {p.get('status')})")

    if report_data.get("headers", {}).get("security"):
        missing = [h for h in report_data["headers"]["security"] if h.get("status") == "MISSING"]
        if missing:
            summary_parts.append(f"\n**Headers de sécurité manquants:**")
            for h in missing:
                summary_parts.append(f"  - {h.get('header')} ({h.get('severity')})")

    if report_data.get("cookies"):
        summary_parts.append(f"\n**Cookies analysés:** {len(report_data['cookies'])}")
        insecure = [c for c in report_data["cookies"] if c.get("issues")]
        if insecure:
            summary_parts.append(f"  - {len(insecure)} cookies avec problèmes de sécurité")

    summary = "\n".join(summary_parts)

    if len(summary) < 100:
        summary += "\n\nPeu de vulnérabilités détectées. Fournis tout de même des recommandations de sécurité générales."

    prompt = USER_PROMPT_TEMPLATE.format(report_summary=summary)

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://secaudit.local",
                "X-Title": "SecAudit AI Analyzer",
            },
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.7,
                "max_tokens": 3000,
            },
            timeout=60,
        )

        if response.status_code == 200:
            data = response.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            if content:
                return (True, content)
            return (False, "AI returned empty response")
        else:
            # Never expose API key or sensitive data in error messages
            if response.status_code == 401:
                return (False, "AI API Error 401: Invalid API key. Check your OPENROUTER_KEY in .env")
            elif response.status_code == 403:
                return (False, "AI API Error 403: Access forbidden. Check your OpenRouter account credits")
            elif response.status_code == 429:
                return (False, "AI API Error 429: Rate limited. Try again in a few seconds")
            else:
                return (False, f"AI API Error {response.status_code}. Check your OpenRouter account.")
    except requests.exceptions.Timeout:
        return (False, "AI request timed out (60s). Try again or use a faster model.")
    except requests.exceptions.ConnectionError as e:
        return (False, f"AI connection error: {str(e)[:100]}")
    except Exception as e:
        return (False, f"AI Error: {str(e)[:200]}")


def get_ai_findings(report_data: dict, target_url: str) -> tuple:
    """Get AI analysis. Returns (success: bool, result: str or error_message)"""
    if not OPENROUTER_KEY:
        return (False, "OPENROUTER_KEY not configured in .env")

    success, result = analyze_with_ai(report_data, target_url)
    if success:
        return (True, result)
    return (False, result)
