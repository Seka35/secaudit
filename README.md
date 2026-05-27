<div align="center">

# 🔮 SECAUDIT : VIBE-SEC SCANNER

<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python Badge"/>
<img src="https://img.shields.io/badge/Status-Next_Gen-ff69b4?style=for-the-badge&logo=rocket&logoColor=white" alt="Status Badge"/>
<img src="https://img.shields.io/badge/Vibe-Max-blueviolet?style=for-the-badge&logo=sparkles&logoColor=white" alt="Vibe Badge"/>

<br><br>

```text
   ▄████████    ▄████████  ▄████████    ▄████████ ███    █▄  ████████▄   ▄█      ███
  ███    ███   ███    ███ ███    ███   ███    ███ ███    ███ ███   ▀███ ███  ▀█████████▄
  ███    █▀    ███    █▀  ███    █▀    ███    ███ ███    ███ ███    ███ ███▌    ▀███▀▀██
  ███         ▄███▄▄▄     ███          ███    ███ ███    ███ ███    ███ ███▌     ███   ▀
▀███████████ ▀▀███▀▀▀     ███        ▀███████████ ███    ███ ███    ███ ███▌     ███
         ███   ███    █▄  ███    █▄    ███    ███ ███    ███ ███    ███ ███      ███
   ▄█    ███   ███    ███ ███    ███   ███    ███ ███    ███ ███   ▄███ ███      ███
 ▄████████▀    ██████████  ████████▀   ███    █▀  ████████▀  ████████▀  █▀      ▄████▀
```

<br>

**The ultimate security scanner built for the Vibe-Coding era.**
SecAudit seamlessly bridges the gap between fast modern AI web development and deep-level offensive security.
*Scan the Frontend. Audit the Infrastructure. Hack the Future.*

</div>

---

## ⚡ ARCHITECTURE & FEATURES

SecAudit isn't just another scanner; it's a multi-layered offensive intelligence tool designed to dissect modern applications built with React, Next.js, and AI code-generation tools.

### 🕸️ 1. Next-Gen Frontend Crawling
- **Next.js Chunk Decompilation**: Automatically discovers `_buildManifest.js` and extracts all dynamically loaded Webpack chunks that standard scanners miss.
- **Vibe-Coding Detection**: Identifies whether the site was built using Cursor, V0, Lovable, or generic AI bootstraps, adapting its threat model accordingly.
- **Deep Source Analysis**: Scans inline scripts, external JS bundles, CSS tokens, and HTML comments for hidden logic.

### 🔑 2. Advanced Secret Hunting (41+ Patterns)
Detects forgotten hardcoded keys with a powerful **Anti-False-Positive** engine that ignores CSS hashes and SRI variables:
- **Cloud/Infra**: AWS, GCP, Azure, Supabase, Firebase.
- **Payments**: Stripe, PayPal, Square.
- **AI/LLMs**: OpenAI, Anthropic, OpenRouter.
- **Communications**: Twilio, SendGrid, Slack, Discord.

### 🔌 3. API & GraphQL Discovery
Active probing of backend data structures:
- **Swagger/OpenAPI Parsing**: Locates hidden `swagger.json` and `api-docs`. Automatically parses the schema, counts endpoints, and flags **Unauthenticated APIs**.
- **GraphQL Introspection**: Fires introspection queries (`__schema`) to uncover fully exposed GraphQL databases.

### 🕵️ 4. OSINT Wayback Machine (Deep Web)
The internet never forgets.
- SecAudit connects to the **Internet Archive CDX API**.
- Downloads historical `.js` and `.env` files that existed on the domain months or years ago.
- Scans these deleted files for exposed secrets that were patched on the live site but remain in the archives.

### ☢️ 5. Nuclei Engine Orchestrator
Bridging Frontend OSINT with Backend Exploitation.
- Automatically orchestrates **ProjectDiscovery's Nuclei** in the background.
- Scans the target for over 8,000+ infrastructure vulnerabilities: CVEs, exposed `.env`, misconfigurations, and server status panels.
- Merges the findings into a unified, beautiful ASCII terminal report.

---

## 🚀 INSTALLATION

SecAudit includes a magic installer that sets up the CLI globally and handles dependencies (including downloading the Nuclei binary automatically if you don't have it!).

```bash
# Clone the repository
git clone https://github.com/Seka35/secaudit.git
cd secaudit

# Run the magic installer
chmod +x install.sh
./install.sh
```

---

## 🎯 USAGE

Start an offensive audit with a single command from anywhere in your terminal:

```bash
secaudit
```

1. You will be greeted by the cyber-terminal UI.
2. Enter your target URL (e.g., `https://example.com`).
3. Watch as SecAudit spins up concurrent threads to rip through the target's stack, history, APIs, and infrastructure.

*(Disclaimer: Use only on systems you own or have explicit permission to test.)*

---

## 🛠️ HOW THE MODULES WORK

### 🤖 The "Vibe" Filter
AI coding assistants often generate generic secrets, dummy data, or CSS classes that look like API keys (e.g., `--token-xyz`). SecAudit uses context-aware regex filtering to ignore these fake keys, ensuring a **zero-noise** report.

### ☢️ The Nuclei Integration
If the `nuclei` binary is found on your system (or installed via `install.sh`), SecAudit runs it silently in the background with targeted tags (`cve, exposure, misconfig, vuln`) and a strict 3-minute timeout to prevent hanging on slow servers.

---

## 🛡️ ACTIONABLE REPORTING

SecAudit doesn't just tell you what's broken; it shows you how to exploit it and how to patch it.
Every High/Critical finding comes with:
- **Exploit**: A ready-to-use `curl` command or CLI snippet to prove the vulnerability.
- **Patch**: Clear, modern remediation advice to secure the codebase.

<br>
<div align="center">
<i>Built for the modern web.</i>
</div>
