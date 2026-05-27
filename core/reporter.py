"""Report generator for SecAudit."""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich import box

SEV_COLORS = {"CRITICAL": "bold white on red", "HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold blue", "INFO": "dim cyan", "OK": "bold green"}
SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪", "OK": "🟢"}

class Reporter:
    def __init__(self, console):
        self.console = console
        self.vuln_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def _sev(self, s):
        return f"[{SEV_COLORS.get(s,'dim')}]{SEV_ICONS.get(s,'')} {s}[/{SEV_COLORS.get(s,'dim')}]"

    def _section(self, title, icon="🔍"):
        self.console.print()
        self.console.print(Panel(f"[bold white]{title}[/bold white]", title=f"[bold cyan]{icon}[/bold cyan]", border_style="cyan", padding=(0, 2)))

    def generate_report(self, results, url):
        self.console.print()
        self.console.print(Panel("[bold white]SECURITY AUDIT REPORT[/bold white]", title="[bold red]☠  SECAUDIT RESULTS[/bold red]", border_style="bright_red", padding=(1, 4)))

        self._report_fetch(results.get("fetch", {}), url)
        self._report_domain(results.get("domain_info", {}))
        self._report_ssl(results.get("ssl", {}))
        self._report_tech(results.get("tech", {}))
        self._report_headers(results.get("headers", {}))
        self._report_vibe_coding(results.get("vibe_coding", []))
        self._report_resources(results.get("resources", {}))
        self._report_secrets(results.get("secrets", []))
        self._report_sensitive_paths(results.get("sensitive_paths", []))
        self._report_cookies(results.get("cookies", []))
        self._report_forms(results.get("forms", []))
        self._report_info_leaks(results.get("info_leaks", []))
        self._report_js(results.get("js_analysis", []))
        self._report_summary()

    def _report_fetch(self, data, url):
        self._section("TARGET INFORMATION", "🎯")
        t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
        t.add_column("Key", style="bold cyan", width=20)
        t.add_column("Value", style="white")
        t.add_row("Target URL", url)
        t.add_row("Final URL", str(data.get("url_final", "N/A")))
        t.add_row("HTTP Status", str(data.get("status", "N/A")))
        t.add_row("Page Size", f"{data.get('size', 0):,} bytes")
        if data.get("url_final", url) != url:
            t.add_row("⚠ Redirect", f"[yellow]Redirected to {data.get('url_final')}[/yellow]")
        self.console.print(t)

    def _report_domain(self, data):
        if not data:
            return
        self._section("DOMAIN & DNS INTELLIGENCE", "🌐")
        t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
        t.add_column("Key", style="bold cyan", width=20)
        t.add_column("Value", style="white")
        t.add_row("Domain", data.get("domain", "N/A"))
        t.add_row("IP Address", data.get("ip", "N/A"))
        dns = data.get("dns", {})
        for rt, vals in dns.items():
            t.add_row(f"DNS {rt}", ", ".join(vals[:5]))
        whois = data.get("whois")
        if whois:
            for k, v in whois.items():
                if v and v != "None":
                    t.add_row(f"WHOIS {k.title()}", str(v)[:80])
        self.console.print(t)

    def _report_ssl(self, data):
        if not data:
            return
        self._section("SSL/TLS ANALYSIS", "🔒")
        status = data.get("status", "UNKNOWN")
        if status == "NOT_HTTPS":
            self.console.print(Panel("[bold red]⚠ SITE IS NOT USING HTTPS![/bold red]\n\n[white]All traffic is transmitted in plaintext. Attackers on the same network can intercept all data including credentials.\n\n[bold]Exploit:[/bold] Use Wireshark or tcpdump to capture plaintext traffic on the same network.\n[bold]Patch:[/bold] Obtain a TLS certificate (Let's Encrypt is free) and enforce HTTPS.[/white]", border_style="red"))
            self.vuln_count["CRITICAL"] += 1
            return
        if status == "ERROR":
            self.console.print(f"[red]SSL Error: {data.get('error', 'Unknown')}[/red]")
            return
        t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
        t.add_column("Key", style="bold cyan", width=20)
        t.add_column("Value", style="white")
        t.add_row("Status", "[green]✓ Valid Certificate[/green]")
        for k in ["version", "notBefore", "notAfter", "issuer", "serial"]:
            if data.get(k):
                t.add_row(k.title(), str(data[k])[:80])
        alts = data.get("alt_names", [])
        if alts:
            t.add_row("Alt Names", ", ".join(alts[:10]))
        self.console.print(t)

    def _report_tech(self, data):
        if not data:
            return
        self._section("TECHNOLOGY STACK", "⚙️")
        detected = data.get("detected", [])
        if detected:
            cats = {"Frontend": ["React", "Vue.js", "Angular", "Svelte", "jQuery", "Bootstrap", "Tailwind CSS"],
                    "Framework": ["Next.js", "Nuxt.js", "Django", "Laravel", "Express.js", "Flask", "Ruby on Rails", "ASP.NET"],
                    "Platform": ["WordPress", "Cloudflare", "Vercel", "Netlify", "Firebase", "Supabase"],
                    "Build": ["Webpack", "Vite"],
                    "Analytics": ["Google Analytics", "Google Tag Manager", "Hotjar", "Sentry"],
                    "Payment": ["Stripe.js"],
                    "Language": ["PHP"],
                    "Vibe-Coding": ["Replit", "Lovable (GPT Engineer)", "Bolt.new", "v0.dev (Vercel)", "Cursor", "Windsurf (Codeium)", "Create.xyz", "Tempo Labs", "Bubble.io", "Webflow", "Framer", "Wix", "Squarespace"]}
            t = Table(box=box.ROUNDED, padding=(0, 2))
            t.add_column("Category", style="bold cyan")
            t.add_column("Technologies", style="white")
            for cat, techs in cats.items():
                found = [x for x in detected if x in techs]
                if found:
                    t.add_row(cat, ", ".join(f"[bold green]{x}[/bold green]" for x in found))
            other = [x for x in detected if not any(x in v for v in cats.values())]
            if other:
                t.add_row("Other", ", ".join(f"[green]{x}[/green]" for x in other))
            self.console.print(t)
        else:
            self.console.print("[dim]No technologies confidently detected.[/dim]")
        meta = data.get("meta", {})
        if meta:
            mt = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            mt.add_column("Meta", style="bold dim", width=25)
            mt.add_column("Value", style="dim")
            for k, v in list(meta.items())[:15]:
                mt.add_row(k, str(v)[:80])
            self.console.print(mt)

    def _report_headers(self, data):
        if not data:
            return
        self._section("HTTP SECURITY HEADERS", "🛡️")
        sec = data.get("security", [])
        t = Table(box=box.ROUNDED, padding=(0, 1))
        t.add_column("Header", style="bold white", width=30)
        t.add_column("Status", width=12)
        t.add_column("Severity", width=12)
        for h in sec:
            status = "[green]✓ Present[/green]" if h["status"] == "PRESENT" else "[red]✗ Missing[/red]"
            t.add_row(h["header"], status, self._sev(h["severity"]))
        self.console.print(t)
        missing = [h for h in sec if h["status"] == "MISSING"]
        for h in missing:
            sev = h["severity"]
            self.vuln_count[sev] = self.vuln_count.get(sev, 0) + 1
            self.console.print(Panel(
                f"[bold]{h['header']}[/bold] — {h['description']}\n\n"
                f"[bold red]Exploit:[/bold red] {h['exploit']}\n\n"
                f"[bold green]Patch:[/bold green] [cyan]{h['patch']}[/cyan]",
                title=f"{self._sev(sev)} Missing Header", border_style="yellow"))
        leaks = data.get("info_leak", [])
        if leaks:
            self.console.print()
            for l in leaks:
                self.vuln_count["LOW"] += 1
                self.console.print(f"  [yellow]⚠ {l['header']}:[/yellow] [white]{l['value']}[/white] — [dim]{l['risk']}[/dim]")

    def _report_vibe_coding(self, tools):
        self._section("VIBE-CODING / AI BUILDER DETECTION", "🤖")
        if not tools:
            self.console.print("[dim]  No vibe-coding or AI builder tools detected.[/dim]")
            return
        self.console.print(f"[bold magenta]  ⚠ Detected {len(tools)} vibe-coding tool(s)![/bold magenta]\n")
        self.console.print(Panel(
            "[bold yellow]⚡ VIBE-CODED APPLICATION DETECTED[/bold yellow]\n\n"
            "[white]This site appears to be built with AI-assisted or no-code tools. "
            "These applications commonly have:[/white]\n"
            "  • Hardcoded API keys in client-side bundles\n"
            "  • Missing or weak authentication middleware\n"
            "  • Default security configurations\n"
            "  • Overly permissive CORS and database rules\n"
            "  • Exposed environment variables in build artifacts",
            border_style="magenta", title="[bold]🚨 VIBE-CODE ALERT[/bold]"))
        for tool in tools:
            self.vuln_count["INFO"] += 1
            self.console.print(Panel(
                f"[bold]Tool:[/bold] [magenta]{tool['tool']}[/magenta]\n"
                f"[bold]What:[/bold] {tool['description']}\n"
                f"[bold]Evidence:[/bold] [dim]{tool['evidence']}[/dim]\n\n"
                f"[bold yellow]Security Risk:[/bold yellow] {tool['risk']}\n\n"
                f"[bold green]Recommendation:[/bold green] Manually review all AI-generated code for hardcoded secrets, "
                f"validate authentication flows, check database security rules, and ensure no development credentials remain in production.",
                title=f"🤖 {tool['tool']}", border_style="bright_magenta"))

    def _report_resources(self, data):
        if not data:
            return
        self._section("CRAWLED RESOURCES", "📦")
        t = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 2))
        t.add_column("Key", style="bold cyan", width=20)
        t.add_column("Value", style="white")
        t.add_row("JS Files", str(data.get("js_count", 0)))
        t.add_row("CSS Files", str(data.get("css_count", 0)))
        t.add_row("Total Source", f"{data.get('total_source_size', 0):,} bytes analyzed")
        self.console.print(t)

    def _report_secrets(self, secrets):
        self._section("SECRET & API KEY SCANNER", "🔑")
        if not secrets:
            self.console.print("[bold green]  ✓ No hardcoded secrets detected.[/bold green]")
            return
        self.console.print(f"[bold red]  ⚠ Found {len(secrets)} potential secret(s)![/bold red]\n")
        for s in secrets:
            sev = s.get("severity", "HIGH")
            self.vuln_count[sev] = self.vuln_count.get(sev, 0) + 1
            exploit_map = {
                "AWS Access Key": (
                    "1. Configure stolen creds:\n"
                    "   aws configure  (paste Access Key + Secret Key)\n"
                    "2. List all S3 buckets:\n"
                    "   curl 'https://s3.amazonaws.com' -H 'Authorization: AWS <KEY>:<SIGNATURE>'\n"
                    "3. Enumerate services:\n"
                    "   aws sts get-caller-identity\n"
                    "   aws s3 ls\n"
                    "   aws iam list-users\n"
                    "   aws ec2 describe-instances\n"
                    "4. Full account takeover possible: create admin users, exfil data, spin up crypto miners."
                ),
                "AWS Secret Key": (
                    "Same as AWS Access Key — used together for full AWS API access.\n"
                    "   aws configure  →  paste both keys\n"
                    "   aws s3 ls / aws iam list-users / aws lambda list-functions"
                ),
                "Google API Key": (
                    "1. Test which Google APIs are enabled:\n"
                    "   curl 'https://maps.googleapis.com/maps/api/geocode/json?address=Paris&key=<KEY>'\n"
                    "   curl 'https://www.googleapis.com/customsearch/v1?q=test&key=<KEY>&cx=...'\n"
                    "   curl 'https://translation.googleapis.com/language/translate/v2?q=hello&target=fr&key=<KEY>'\n"
                    "2. Check billing: unrestricted keys can rack up charges on Maps, Translate, Vision, YouTube APIs.\n"
                    "3. If Firebase key: test Firestore/RTDB access with the key.\n"
                    "4. Abuse possibilities: free geocoding, translation, AI services on victim's bill."
                ),
                "Stripe Secret Key": (
                    "1. List all customers and their payment methods:\n"
                    "   curl https://api.stripe.com/v1/customers -u sk_live_XXXX:\n"
                    "2. List all charges (transaction history):\n"
                    "   curl https://api.stripe.com/v1/charges?limit=100 -u sk_live_XXXX:\n"
                    "3. Create a refund (steal money):\n"
                    "   curl https://api.stripe.com/v1/refunds -u sk_live_XXXX: -d charge=ch_xxx\n"
                    "4. Access PII: names, emails, addresses, last4 of cards.\n"
                    "5. Create charges, modify subscriptions, export full customer database."
                ),
                "Stripe Publishable Key": (
                    "1. Publishable keys are meant for frontend but can reveal:\n"
                    "   - Stripe account ID\n"
                    "   - Active payment configurations\n"
                    "2. If paired with a secret key elsewhere, full account compromise.\n"
                    "3. Can be used to tokenize cards and test payment flows."
                ),
                "OpenAI API Key": (
                    "1. List available models:\n"
                    "   curl https://api.openai.com/v1/models -H 'Authorization: Bearer sk-XXXX'\n"
                    "2. Make expensive API calls (GPT-4, DALL-E):\n"
                    "   curl https://api.openai.com/v1/chat/completions \\\n"
                    "     -H 'Authorization: Bearer sk-XXXX' \\\n"
                    "     -H 'Content-Type: application/json' \\\n"
                    "     -d '{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'\n"
                    "3. Generate images at victim's cost:\n"
                    "   curl https://api.openai.com/v1/images/generations ...\n"
                    "4. Can run up thousands in API charges in minutes."
                ),
                "Anthropic API Key": (
                    "1. Make Claude API calls at victim's expense:\n"
                    "   curl https://api.anthropic.com/v1/messages \\\n"
                    "     -H 'x-api-key: sk-ant-XXXX' \\\n"
                    "     -H 'anthropic-version: 2023-06-01' \\\n"
                    "     -H 'Content-Type: application/json' \\\n"
                    "     -d '{\"model\":\"claude-sonnet-4-20250514\",\"max_tokens\":1024,\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'\n"
                    "2. Use Claude Opus for expensive long-context tasks.\n"
                    "3. Bills can escalate to hundreds/day with automated abuse."
                ),
                "OpenRouter API Key": (
                    "1. Route calls to ANY LLM provider (OpenAI, Anthropic, Google, etc.):\n"
                    "   curl https://openrouter.ai/api/v1/chat/completions \\\n"
                    "     -H 'Authorization: Bearer sk-or-v1-XXXX' \\\n"
                    "     -H 'Content-Type: application/json' \\\n"
                    "     -d '{\"model\":\"anthropic/claude-sonnet-4-20250514\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'\n"
                    "2. Access to 100+ models through a single stolen key.\n"
                    "3. Can abuse credits across multiple providers simultaneously."
                ),
                "GitHub Token": (
                    "1. List private repos:\n"
                    "   curl -H 'Authorization: token ghp_XXXX' https://api.github.com/user/repos?type=private\n"
                    "2. Clone private source code:\n"
                    "   git clone https://ghp_XXXX@github.com/org/private-repo.git\n"
                    "3. Read secrets in repo settings:\n"
                    "   curl -H 'Authorization: token ghp_XXXX' https://api.github.com/repos/org/repo/actions/secrets\n"
                    "4. Push malicious code, create backdoored releases, access CI/CD pipelines."
                ),
                "Slack Token": (
                    "1. List all channels and messages:\n"
                    "   curl 'https://slack.com/api/conversations.list' -H 'Authorization: Bearer xoxb-XXXX'\n"
                    "2. Read message history:\n"
                    "   curl 'https://slack.com/api/conversations.history?channel=C123' -H 'Authorization: Bearer xoxb-XXXX'\n"
                    "3. Post messages as bot/user:\n"
                    "   curl -X POST 'https://slack.com/api/chat.postMessage' -H 'Authorization: Bearer xoxb-XXXX' \\\n"
                    "     -d 'channel=C123&text=Phishing link here'\n"
                    "4. Download shared files, list users, exfiltrate entire workspace."
                ),
                "Discord Webhook": (
                    "1. Post messages to channel:\n"
                    "   curl -X POST 'WEBHOOK_URL' -H 'Content-Type: application/json' \\\n"
                    "     -d '{\"content\":\"Phishing message from compromised webhook\"}'\n"
                    "2. Send embedded phishing content with custom username/avatar.\n"
                    "3. Spam or social engineer server members."
                ),
                "Discord Bot Token": (
                    "1. Login as bot and access all guilds:\n"
                    "   curl -H 'Authorization: Bot TOKEN' https://discord.com/api/v10/users/@me/guilds\n"
                    "2. Read all messages, manage channels, kick/ban users.\n"
                    "3. Full server takeover if bot has admin permissions."
                ),
                "Database URL": (
                    "1. Connect directly to database:\n"
                    "   psql 'postgresql://user:pass@host:5432/db'  (PostgreSQL)\n"
                    "   mysql -h host -u user -p'pass' db  (MySQL)\n"
                    "   mongosh 'mongodb://user:pass@host:27017/db'  (MongoDB)\n"
                    "2. Dump all tables: SELECT * FROM users; SELECT * FROM payments;\n"
                    "3. Exfiltrate full database, modify records, drop tables.\n"
                    "4. Access PII, credentials, payment data — FULL DATA BREACH."
                ),
                "JWT Token": (
                    "1. Decode payload (no key needed):\n"
                    "   echo 'TOKEN' | cut -d. -f2 | base64 -d\n"
                    "2. Use token to access protected API endpoints:\n"
                    "   curl -H 'Authorization: Bearer TOKEN' https://target.com/api/user\n"
                    "3. If secret is weak, crack it: hashcat -m 16500 token.txt wordlist.txt\n"
                    "4. Forge new tokens with modified claims (admin role, different user ID)."
                ),
                "Firebase API Key": (
                    "1. Test Firestore access:\n"
                    "   curl 'https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/users?key=KEY'\n"
                    "2. Test Realtime Database:\n"
                    "   curl 'https://PROJECT.firebaseio.com/.json'\n"
                    "3. If security rules are { \".read\": true }, entire database is exposed.\n"
                    "4. Check auth: curl 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=KEY' -d '{\"returnSecureToken\":true}'"
                ),
                "Firebase URL": (
                    "1. Try reading the entire database:\n"
                    "   curl 'https://PROJECT.firebaseio.com/.json'\n"
                    "2. If rules allow: curl 'https://PROJECT.firebaseio.com/users.json'\n"
                    "3. Write data: curl -X PUT 'https://PROJECT.firebaseio.com/test.json' -d '{\"pwned\":true}'\n"
                    "4. Common in vibe-coded apps with default open rules."
                ),
                "SendGrid API Key": (
                    "1. Send emails as the victim's domain:\n"
                    "   curl -X POST 'https://api.sendgrid.com/v3/mail/send' \\\n"
                    "     -H 'Authorization: Bearer SG.XXXX' \\\n"
                    "     -H 'Content-Type: application/json' \\\n"
                    "     -d '{\"personalizations\":[{\"to\":[{\"email\":\"target@email.com\"}]}],\"from\":{\"email\":\"ceo@victim.com\"},\"subject\":\"Urgent\",\"content\":[{\"type\":\"text/plain\",\"value\":\"...\"}]}'\n"
                    "2. Phishing campaigns from trusted domain, spam, reputation damage."
                ),
                "Twilio API Key": (
                    "1. Send SMS from victim's number:\n"
                    "   curl -X POST 'https://api.twilio.com/2010-04-01/Accounts/ACXXX/Messages.json' \\\n"
                    "     -u 'ACXXX:AUTH_TOKEN' \\\n"
                    "     -d 'To=+1234567890&From=+0987654321&Body=Phishing SMS'\n"
                    "2. Make phone calls, access call logs, read SMS history.\n"
                    "3. Run up charges with premium rate numbers."
                ),
                "Supabase Key": (
                    "1. Access Supabase REST API:\n"
                    "   curl 'https://PROJECT.supabase.co/rest/v1/users?select=*' \\\n"
                    "     -H 'apikey: ANON_KEY' -H 'Authorization: Bearer ANON_KEY'\n"
                    "2. If RLS policies are weak, read/write all tables.\n"
                    "3. Check auth: curl 'https://PROJECT.supabase.co/auth/v1/signup' ...\n"
                    "4. Very common in Lovable/Bolt.new apps with default permissive policies."
                ),
                "Heroku API Key": (
                    "1. List all apps:\n"
                    "   curl -n https://api.heroku.com/apps \\\n"
                    "     -H 'Authorization: Bearer TOKEN' \\\n"
                    "     -H 'Accept: application/vnd.heroku+json; version=3'\n"
                    "2. Read config vars (contains all env secrets):\n"
                    "   curl https://api.heroku.com/apps/APP_NAME/config-vars \\\n"
                    "     -H 'Authorization: Bearer TOKEN' ...\n"
                    "3. Deploy malicious code, access databases, exfiltrate all environment variables."
                ),
                "Mapbox Token": (
                    "1. Use Maps/Geocoding at victim's expense:\n"
                    "   curl 'https://api.mapbox.com/geocoding/v5/mapbox.places/Paris.json?access_token=TOKEN'\n"
                    "2. Access Mapbox APIs: directions, tilesets, datasets.\n"
                    "3. Run up charges on victim's billing account."
                ),
            }
            patch_map = {
                "AWS Access Key": "1. IMMEDIATELY rotate in AWS IAM Console → Users → Security credentials.\n2. Use AWS Secrets Manager or SSM Parameter Store.\n3. Never hardcode — use IAM roles for EC2/Lambda.\n4. Enable CloudTrail to audit what the leaked key accessed.",
                "AWS Secret Key": "Same as AWS Access Key — rotate both together in IAM Console.",
                "Google API Key": "1. Go to Google Cloud Console → APIs & Services → Credentials.\n2. Add HTTP referrer restrictions (your domain only).\n3. Add API restrictions (only enable needed APIs).\n4. For sensitive APIs (Cloud, AI), use server-side service accounts instead.\n5. Rotate the key after restricting.",
                "Stripe Secret Key": "1. IMMEDIATELY rotate in Stripe Dashboard → Developers → API Keys → Roll Key.\n2. Secret keys must NEVER be in frontend code.\n3. Use server-side API route as proxy (e.g., /api/stripe/charge).\n4. Enable Stripe webhook signatures for server verification.",
                "Stripe Publishable Key": "Publishable keys are designed for frontend, but:\n1. Ensure no secret key is also exposed.\n2. Set up domain restrictions in Stripe Dashboard.\n3. Monitor for unexpected charges.",
                "OpenAI API Key": "1. Rotate at platform.openai.com → API Keys → Create new → Delete old.\n2. Create a server-side proxy: /api/ai/chat → forwards to OpenAI.\n3. Set usage limits in OpenAI dashboard.\n4. Use per-project keys with minimal permissions.",
                "Anthropic API Key": "1. Rotate at console.anthropic.com → API Keys.\n2. Build a backend proxy endpoint.\n3. Set workspace spending limits.\n4. Never expose in client-side JavaScript bundles.",
                "OpenRouter API Key": "1. Rotate at openrouter.ai → Settings → API Keys.\n2. Create a backend proxy endpoint.\n3. Set per-model and total spending limits.\n4. Use separate keys per environment.",
                "GitHub Token": "1. Revoke at GitHub → Settings → Developer settings → Personal access tokens.\n2. Use fine-grained tokens with minimal scope and expiry.\n3. For CI/CD, use GITHUB_TOKEN (automatic, scoped to repo).\n4. Store in GitHub Actions secrets, not code.",
                "Slack Token": "1. Revoke at api.slack.com → Your Apps → OAuth & Permissions.\n2. Use proper OAuth 2.0 flow instead of hardcoded tokens.\n3. Request minimum scopes needed.\n4. Rotate regularly.",
                "Discord Webhook": "1. Delete webhook in Discord Server Settings → Integrations.\n2. Create a new webhook URL.\n3. Never expose webhook URLs in client-side code.\n4. Use server-side proxy to post messages.",
                "Discord Bot Token": "1. Regenerate at discord.com/developers → Bot → Reset Token.\n2. Store in environment variables only.\n3. Grant minimum permissions (principle of least privilege).",
                "Database URL": "1. IMMEDIATELY change database password.\n2. Move connection string to server-side environment variables.\n3. Use connection pooling (PgBouncer, etc.) with restricted user.\n4. Enable SSL for database connections.\n5. Restrict DB access to application server IPs only.",
                "JWT Token": "1. Invalidate the token (add to blocklist or change signing secret).\n2. Implement proper token rotation with short expiry (15-30 min).\n3. Store in HttpOnly, Secure, SameSite cookies — never localStorage.\n4. Use strong signing secrets (256+ bits).",
                "Firebase API Key": "1. Set proper Firestore Security Rules (deny by default).\n2. Set proper Realtime Database rules.\n3. Restrict API key in Google Cloud Console.\n4. API key alone shouldn't grant access if rules are correct — but verify rules!",
                "Firebase URL": "1. Set security rules: { \".read\": \"auth != null\", \".write\": \"auth != null\" }\n2. Never use { \".read\": true } in production.\n3. Validate all data writes with rules.\n4. Use Firebase App Check for additional protection.",
                "SendGrid API Key": "1. Revoke in SendGrid → Settings → API Keys.\n2. Create new key with minimum permissions (Mail Send only).\n3. Use server-side only — never expose in frontend.",
                "Twilio API Key": "1. Revoke at twilio.com → Console → API Keys.\n2. Create new key with minimum permissions.\n3. Enable geographic permissions to prevent premium SMS abuse.",
                "Supabase Key": "1. Enable Row Level Security (RLS) on ALL tables.\n2. Write proper RLS policies for each table.\n3. The anon key is public by design, but RLS must protect data.\n4. Use service_role key only server-side.\n5. Test: can an anonymous user read/write data they shouldn't?",
                "Heroku API Key": "1. Rotate at Heroku Dashboard → Account Settings → API Key → Regenerate.\n2. Use Heroku CLI auth (heroku login) instead of hardcoded keys.\n3. Store in environment variables (heroku config:set).",
                "Mapbox Token": "1. Rotate at mapbox.com → Account → Access tokens.\n2. Set URL restrictions on the token.\n3. Use separate tokens for dev/prod.",
            }
            default_exploit = (
                "1. Extract the secret from the page source or JS bundle.\n"
                "2. Use it to authenticate against the associated API.\n"
                "3. Depending on the service: access data, make charges, send messages, or modify resources.\n"
                "4. Automate abuse with scripts to maximize impact before detection."
            )
            default_patch = "1. Remove from source code IMMEDIATELY.\n2. Store in environment variables (.env) loaded server-side only.\n3. Create a backend API proxy so the key never reaches the browser.\n4. Rotate the compromised credential at the provider's dashboard.\n5. Audit logs for unauthorized usage during exposure period."
            typ = s["type"]
            self.console.print(Panel(
                f"[bold]Type:[/bold] {typ}\n"
                f"[bold]Value:[/bold] [red]{s['value_masked']}[/red]\n"
                f"[bold]Location:[/bold] {s['location']}\n"
                f"[bold]Context:[/bold] [dim]{s['context']}[/dim]\n\n"
                f"[bold red]━━━ EXPLOIT ━━━[/bold red]\n{exploit_map.get(typ, default_exploit)}\n\n"
                f"[bold green]━━━ PATCH ━━━[/bold green]\n{patch_map.get(typ, default_patch)}",
                title=f"{self._sev(sev)} Secret Exposed: {typ}", border_style="red"))

    def _report_sensitive_paths(self, paths):
        self._section("SENSITIVE FILE EXPOSURE", "📂")
        if not paths:
            self.console.print("[bold green]  ✓ No sensitive files exposed.[/bold green]")
            return
        for p in paths:
            sev = p.get("severity", "HIGH")
            self.vuln_count[sev] = self.vuln_count.get(sev, 0) + 1
            path_exploits = {
                "/.env": ("Read environment variables containing secrets, DB creds, API keys.", "Block access via web server config. Add .env to .gitignore."),
                "/.git/config": ("Clone entire source code: git-dumper to reconstruct repo history.", "Block /.git/ path in web server. Remove .git from deployment."),
                "/package.json": ("Enumerate dependencies, find vulnerable versions.", "Remove from public access or restrict path."),
                "/robots.txt": ("Discover hidden paths the site doesn't want indexed.", "Review entries — don't list truly sensitive paths here."),
            }
            default_exp = ("Access sensitive configuration or data files.", "Block public access via web server configuration (nginx/apache).")
            exp, patch = path_exploits.get(p["path"], default_exp)
            self.console.print(Panel(
                f"[bold]Path:[/bold] {p['path']}\n"
                f"[bold]Status:[/bold] {p['status']} | [bold]Size:[/bold] {p['size']:,} bytes\n"
                f"[bold]Preview:[/bold] [dim]{p['snippet'][:100]}[/dim]\n\n"
                f"[bold red]Exploit:[/bold red] {exp}\n"
                f"[bold green]Patch:[/bold green] {patch}",
                title=f"{self._sev(sev)} Exposed: {p['path']}", border_style="yellow"))

    def _report_cookies(self, cookies):
        if not cookies:
            return
        self._section("COOKIE SECURITY", "🍪")
        has_issues = any(c.get("issues") for c in cookies)
        t = Table(box=box.ROUNDED, padding=(0, 1))
        t.add_column("Name", style="bold white")
        t.add_column("Secure", width=8)
        t.add_column("HttpOnly", width=10)
        t.add_column("SameSite", width=10)
        t.add_column("Issues", style="yellow")
        for c in cookies:
            sec = "[green]✓[/green]" if c["secure"] else "[red]✗[/red]"
            http = "[green]✓[/green]" if c["httponly"] else "[red]✗[/red]"
            ss = c["samesite"]
            issues = "; ".join(c.get("issues", []))[:60]
            t.add_row(c["name"], sec, http, str(ss), issues)
            if c.get("issues"):
                self.vuln_count["MEDIUM"] += len(c["issues"])
        self.console.print(t)
        if has_issues:
            self.console.print(Panel(
                "[bold red]Exploit:[/bold red] Insecure cookies can be stolen via XSS (no HttpOnly), sent over HTTP (no Secure), or used in CSRF attacks (no SameSite).\n\n"
                "[bold green]Patch:[/bold green] Set all cookies with: Secure; HttpOnly; SameSite=Strict (or Lax for auth cookies).",
                title="⚠ Cookie Security Issues", border_style="yellow"))

    def _report_forms(self, forms):
        if not forms:
            return
        self._section("FORM SECURITY ANALYSIS", "📝")
        for i, f in enumerate(forms):
            issues = f.get("issues", [])
            color = "red" if issues else "green"
            inputs_str = ", ".join(f"{inp['type']}({inp['name']})" for inp in f.get("inputs", [])[:8])
            self.console.print(Panel(
                f"[bold]Action:[/bold] {f['action']}\n"
                f"[bold]Method:[/bold] {f['method']}\n"
                f"[bold]CSRF Token:[/bold] {'[green]✓ Yes[/green]' if f['has_csrf'] else '[red]✗ No[/red]'}\n"
                f"[bold]Inputs:[/bold] {inputs_str}" +
                (f"\n\n[bold red]Issues:[/bold red]\n" + "\n".join(f"  • {iss}" for iss in issues) if issues else ""),
                title=f"Form #{i+1}", border_style=color))
            if issues:
                self.vuln_count["MEDIUM"] += len(issues)

    def _report_info_leaks(self, leaks):
        if not leaks:
            return
        self._section("INFORMATION LEAKS", "💧")
        for l in leaks:
            sev = l.get("severity", "MEDIUM")
            self.vuln_count[sev] = self.vuln_count.get(sev, 0) + 1
            self.console.print(Panel(
                f"[bold]{l['type']}[/bold]\n[dim]{l['content'][:150]}[/dim]\n\n"
                f"[bold red]Exploit:[/bold red] Exposed debug info or source maps let attackers understand app internals and find vulnerabilities.\n"
                f"[bold green]Patch:[/bold green] Remove debug info and source maps from production builds.",
                title=self._sev(sev), border_style="yellow"))

    def _report_js(self, findings):
        if not findings:
            return
        self._section("JAVASCRIPT SECURITY ANALYSIS", "⚡")
        t = Table(box=box.ROUNDED, padding=(0, 1))
        t.add_column("Pattern", style="bold white", width=18)
        t.add_column("Risk", style="yellow", width=35)
        t.add_column("Source", style="dim", width=35)
        for f in findings[:20]:
            t.add_row(f["pattern"], f["description"][:35], f["source"][-35:])
        self.console.print(t)
        dangerous = [f for f in findings if f["pattern"] in ("eval(", "innerHTML", "document.write(")]
        if dangerous:
            self.console.print(Panel(
                "[bold red]Exploit:[/bold red] Functions like eval(), innerHTML, and document.write() can execute attacker-controlled input, leading to XSS.\n\n"
                "[bold green]Patch:[/bold green] Replace eval() with JSON.parse(). Use textContent instead of innerHTML. Use DOM APIs instead of document.write().",
                title="⚠ Dangerous JS Patterns", border_style="yellow"))

    def _report_summary(self):
        self.console.print()
        total = sum(self.vuln_count.values())
        t = Table(box=box.HEAVY, title="[bold white]VULNERABILITY SUMMARY[/bold white]", padding=(0, 3))
        t.add_column("Severity", style="bold white", width=15)
        t.add_column("Count", justify="center", width=10)
        t.add_column("Bar", width=30)
        max_v = max(self.vuln_count.values()) if self.vuln_count.values() else 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = self.vuln_count.get(sev, 0)
            bar_len = int((count / max(max_v, 1)) * 25) if count else 0
            bar = "█" * bar_len
            color = SEV_COLORS.get(sev, "white")
            t.add_row(self._sev(sev), str(count), f"[{color}]{bar}[/{color}]")
        self.console.print(t)
        if total == 0:
            grade, gcolor = "A+", "bold green"
        elif self.vuln_count.get("CRITICAL", 0) > 0:
            grade, gcolor = "F", "bold white on red"
        elif self.vuln_count.get("HIGH", 0) > 2:
            grade, gcolor = "D", "bold red"
        elif self.vuln_count.get("HIGH", 0) > 0:
            grade, gcolor = "C", "bold yellow"
        elif self.vuln_count.get("MEDIUM", 0) > 3:
            grade, gcolor = "B-", "bold yellow"
        else:
            grade, gcolor = "B+", "bold green"
        self.console.print()
        self.console.print(Panel(
            f"[{gcolor}]  SECURITY GRADE: {grade}  [/{gcolor}]\n\n"
            f"[white]Total findings: {total}[/white]",
            title="[bold]FINAL SCORE[/bold]", border_style="bright_red", padding=(1, 6)))
