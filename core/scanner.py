"""Core scanner engine for SecAudit."""
import re, ssl, socket, hashlib, json, time, platform
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.patterns import SECRET_PATTERNS, SECURITY_HEADERS, SENSITIVE_PATHS, TECH_SIGNATURES, VIBE_CODING_SIGNATURES

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"

class SecurityScanner:
    def __init__(self, url, console):
        self.url = url
        self.console = console
        self.parsed = urlparse(url)
        self.domain = self.parsed.hostname
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.session.verify = True
        self.soup = None
        self.page_text = ""
        self.response = None
        self.js_contents = []
        self.css_contents = []
        self.all_source = ""
        self.wordpress_detected = False
        self.github_detected = False

    def _fetch(self, url, timeout=10):
        try:
            return self.session.get(url, timeout=timeout, allow_redirects=True)
        except:
            return None

    def run_full_scan(self, reporter=None):
        results = {}
        # Map each scanner module to its corresponding reporter method and expected result key
        modules = [
            ("Fetching page", self.fetch_page, "fetch", reporter._report_fetch if reporter else None),
            ("Analyzing DNS & domain", self.scan_domain, "domain_info", reporter._report_domain if reporter else None),
            ("Analyzing HTTP headers", self.scan_headers, "headers", reporter._report_headers if reporter else None),
            ("Analyzing SSL/TLS", self.scan_ssl, "ssl", reporter._report_ssl if reporter else None),
            ("Detecting technology stack", self.scan_tech, "tech", reporter._report_tech if reporter else None),
            ("Detecting vibe-coding tools", self.scan_vibe_coding, "vibe_coding", reporter._report_vibe_coding if reporter else None),
            ("Crawling linked resources", self.crawl_resources, "resources", reporter._report_resources if reporter else None),
            ("Hunting historical secrets (Wayback OSINT)", self.scan_wayback, "wayback", None), # Silently run, no dedicated report
            ("Scanning for secrets", self.scan_secrets, "secrets", reporter._report_secrets if reporter else None),
            ("Checking sensitive paths", self.scan_sensitive_paths, "sensitive_paths", reporter._report_sensitive_paths if reporter else None),
            ("Analyzing cookies", self.scan_cookies, "cookies", reporter._report_cookies if reporter else None),
            ("Analyzing forms", self.scan_forms, "forms", reporter._report_forms if reporter else None),
            ("Checking for info leaks", self.scan_info_leaks, "info_leaks", reporter._report_info_leaks if reporter else None),
            ("Analyzing JavaScript", self.scan_js_deep, "js_analysis", reporter._report_js if reporter else None),
            ("Probing API & GraphQL endpoints", self.scan_api_endpoints, "api_discovery", reporter._report_api_discovery if reporter else None),
            ("WordPress Security Scan (WPScan)", self.scan_wpscan, "wpscan", reporter._report_wpscan if reporter else None),
            ("Git Repository Scan (Gitleaks)", self.scan_gitleaks, "gitleaks", reporter._report_gitleaks if reporter else None),
        ]

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
        from core.ai_analyzer import get_ai_findings
        import concurrent.futures

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as prog:
            task_id = prog.add_task("Initializing...", total=len(modules))

            for desc, fn, result_key, rep_fn in modules:
                prog.update(task_id, description=f"[bold cyan]{desc}")
                try:
                    r = fn()
                    if r:
                        results.update(r)
                        if rep_fn:
                            if result_key == "fetch":
                                rep_fn(r.get(result_key, {}), self.url)
                            else:
                                rep_fn(r.get(result_key, [] if isinstance(r.get(result_key), list) else {}))
                except Exception as e:
                    results[desc] = {"error": str(e)}
                prog.advance(task_id)

        # AI analysis runs AFTER progress bar is closed
        if reporter:
            self.console.print()
            self.console.print("[bold yellow]🤖 Running AI exploitation analysis (~30s)...[/bold yellow]")
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(get_ai_findings, results, self.url)
                    try:
                        success, ai_result = future.result(timeout=90)
                        if success and ai_result and len(ai_result) > 20:
                            results["ai_analysis"] = ai_result
                            self.console.print("[bold green]✓ AI analysis complete![/bold green]")
                            reporter._report_ai_analysis(ai_result)
                        elif ai_result:
                            self.console.print(f"[yellow]⚠ AI: {ai_result[:150]}[/yellow]")
                        else:
                            self.console.print("[dim]⚠ AI: empty response[/dim]")
                    except concurrent.futures.TimeoutError:
                        self.console.print("[yellow]⚠ AI timeout (90s)[/yellow]")
                    except Exception as ai_err:
                        self.console.print(f"[yellow]⚠ AI error: {str(ai_err)[:150]}[/yellow]")
            except Exception as e:
                self.console.print(f"[yellow]⚠ AI module error: {str(e)[:150]}[/yellow]")

        return results

    def fetch_page(self):
        self.response = self._fetch(self.url)
        if not self.response:
            raise ConnectionError(f"Cannot reach {self.url}")
        self.page_text = self.response.text
        self.soup = BeautifulSoup(self.page_text, "html.parser")
        return {"fetch": {"status": self.response.status_code, "size": len(self.page_text), "url_final": self.response.url}}

    def scan_domain(self):
        info = {"domain": self.domain, "ip": None, "dns": {}}
        try:
            info["ip"] = socket.gethostbyname(self.domain)
        except:
            pass
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            for rt in ["A", "AAAA", "MX", "NS", "TXT"]:
                try:
                    ans = resolver.resolve(self.domain, rt)
                    info["dns"][rt] = [str(r) for r in ans]
                except:
                    pass
        except ImportError:
            pass
        try:
            from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
            import whois
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(whois.whois, self.domain)
                w = future.result(timeout=5)
                info["whois"] = {"registrar": getattr(w, "registrar", None), "creation": str(getattr(w, "creation_date", "")), "expiration": str(getattr(w, "expiration_date", "")), "name_servers": getattr(w, "name_servers", None), "org": getattr(w, "org", None), "country": getattr(w, "country", None)}
        except:
            info["whois"] = None
        return {"domain_info": info}

    def scan_headers(self):
        if not self.response:
            return {}
        hdrs = dict(self.response.headers)
        findings = []
        for h, cfg in SECURITY_HEADERS.items():
            present = any(k.lower() == h.lower() for k in hdrs)
            if cfg["expected"] and not present:
                findings.append({"header": h, "status": "MISSING", "severity": cfg["severity"], "description": cfg["description"], "exploit": cfg["exploit"], "patch": cfg["patch"]})
            elif present:
                findings.append({"header": h, "status": "PRESENT", "severity": "OK", "value": hdrs.get(h, hdrs.get(h.lower(), ""))})
        server = hdrs.get("Server", hdrs.get("server", ""))
        powered = hdrs.get("X-Powered-By", hdrs.get("x-powered-by", ""))
        info_leak = []
        if server:
            info_leak.append({"header": "Server", "value": server, "risk": "Server version disclosure"})
        if powered:
            info_leak.append({"header": "X-Powered-By", "value": powered, "risk": "Technology disclosure"})
        return {"headers": {"raw": hdrs, "security": findings, "info_leak": info_leak}}

    def scan_ssl(self):
        if self.parsed.scheme != "https":
            return {"ssl": {"status": "NOT_HTTPS", "severity": "CRITICAL"}}
        info = {}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(5)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                info["subject"] = str(cert.get("subject", ""))
                info["issuer"] = str(cert.get("issuer", ""))
                info["notBefore"] = cert.get("notBefore", "")
                info["notAfter"] = cert.get("notAfter", "")
                info["version"] = s.version()
                san = cert.get("subjectAltName", [])
                info["alt_names"] = [v for _, v in san]
                info["serial"] = cert.get("serialNumber", "")
                info["status"] = "VALID"
        except Exception as e:
            info["status"] = "ERROR"
            info["error"] = str(e)
        return {"ssl": info}

    def scan_tech(self):
        if not self.response:
            return {}
        detected = []
        combined = self.page_text + " " + str(self.response.headers)
        for tech, patterns in TECH_SIGNATURES.items():
            for p in patterns:
                if re.search(p, combined, re.IGNORECASE):
                    detected.append(tech)
                    if tech == "WordPress":
                        self.wordpress_detected = True
                    break
        meta = {}
        if self.soup:
            gen = self.soup.find("meta", attrs={"name": "generator"})
            if gen:
                meta["generator"] = gen.get("content", "")
                if "wordpress" in gen.get("content", "").lower():
                    self.wordpress_detected = True
            for m in self.soup.find_all("meta"):
                name = m.get("name", m.get("property", ""))
                if name:
                    meta[name] = m.get("content", "")

        # Detect GitHub links in source
        if re.search(r"github\.com/[\w-]+/[\w.-]+", self.all_source or self.page_text):
            self.github_detected = True

        return {"tech": {"detected": list(set(detected)), "meta": meta}}

    def scan_vibe_coding(self):
        """Detect vibe-coding / AI builder tools from source and headers."""
        if not self.response:
            return {}
        combined = self.page_text + " " + str(self.response.headers) + " " + str(self.response.url)
        # Also check all already-fetched JS/CSS
        for js in self.js_contents:
            combined += " " + js["content"]
        detected = []
        for tool_name, tool_data in VIBE_CODING_SIGNATURES.items():
            for p in tool_data["patterns"]:
                if re.search(p, combined, re.IGNORECASE):
                    match = re.search(p, combined, re.IGNORECASE)
                    ctx_start = max(0, match.start() - 40)
                    ctx_end = min(len(combined), match.end() + 40)
                    evidence = combined[ctx_start:ctx_end].replace("\n", " ").strip()
                    detected.append({
                        "tool": tool_name,
                        "description": tool_data["description"],
                        "risk": tool_data["risk"],
                        "evidence": evidence[:120],
                        "matched_pattern": p,
                    })
                    break
        return {"vibe_coding": detected}

    def crawl_resources(self):
        if not self.soup:
            return {}
        scripts, styles, links_found = [], [], []
        for s in self.soup.find_all("script"):
            src = s.get("src")
            if src:
                full = urljoin(self.url, src)
                scripts.append(full)
                r = self._fetch(full)
                if r and r.status_code == 200:
                    self.js_contents.append({"url": full, "content": r.text})
            elif s.string:
                self.js_contents.append({"url": "inline", "content": s.string})
        for link in self.soup.find_all("link", rel="stylesheet"):
            href = link.get("href")
            if href:
                full = urljoin(self.url, href)
                styles.append(full)
                r = self._fetch(full)
                if r and r.status_code == 200:
                    self.css_contents.append({"url": full, "content": r.text})
        for st in self.soup.find_all("style"):
            if st.string:
                self.css_contents.append({"url": "inline", "content": st.string})

        # --- Deep crawl: Next.js chunks ---
        self._crawl_nextjs_chunks(scripts)

        # --- Deep crawl: discover JS files referenced in already-fetched JS ---
        self._crawl_referenced_js()

        self.all_source = self.page_text
        for js in self.js_contents:
            self.all_source += "\n" + js["content"]
        for css in self.css_contents:
            self.all_source += "\n" + css["content"]
        return {"resources": {"scripts": scripts, "stylesheets": styles, "js_count": len(self.js_contents), "css_count": len(self.css_contents), "total_source_size": len(self.all_source)}}

    def _crawl_nextjs_chunks(self, scripts):
        """Discover and fetch Next.js static chunks (pages, webpack)."""
        build_id = None
        # Extract buildId from __NEXT_DATA__
        for js in self.js_contents:
            if js["url"] == "inline" and "__NEXT_DATA__" in js["content"]:
                m = re.search(r'"buildId"\s*:\s*"([^"]+)"', js["content"])
                if m:
                    build_id = m.group(1)
                    break

        if not build_id:
            return

        base = f"{self.parsed.scheme}://{self.parsed.netloc}"

        # Fetch build manifest to discover all page chunks
        manifest_url = f"{base}/_next/static/{build_id}/_buildManifest.js"
        r = self._fetch(manifest_url)
        if r and r.status_code == 200:
            self.js_contents.append({"url": manifest_url, "content": r.text})
            # Extract chunk paths from manifest
            chunk_paths = re.findall(r'"(/_next/static/[^"]+\.js)"', r.text)
            # Also extract from self.__BUILD_MANIFEST format
            chunk_paths += re.findall(r'"([^"]+\.js)"', r.text)

            from concurrent.futures import ThreadPoolExecutor, as_completed
            seen = {js["url"] for js in self.js_contents}

            def fetch_chunk(path):
                if path.startswith("http"):
                    url = path
                elif path.startswith("/"):
                    url = base + path
                elif path.startswith("static/"):
                    url = f"{base}/_next/{path}"
                else:
                    url = f"{base}/_next/static/{path}"

                if url in seen:
                    return None
                resp = self._fetch(url, timeout=5)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    return {"url": url, "content": resp.text}
                return None

            # Limit to 30 chunks to avoid slow scans
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(fetch_chunk, p): p for p in chunk_paths[:30]}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        self.js_contents.append(result)
                        seen.add(result["url"])

        # Also try to discover page-specific chunks from script tags
        for s_url in scripts:
            if "/_next/static/chunks/pages/" in s_url or "/_next/static/chunks/app/" in s_url:
                # Already fetched via normal script crawl
                continue

    def _crawl_referenced_js(self):
        """Find JS file references inside already-fetched JS and fetch them."""
        base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        seen = {js["url"] for js in self.js_contents}
        new_urls = set()

        for js in self.js_contents:
            # Find static chunk references like "static/chunks/abc123.js"
            refs = re.findall(r'["\']((?:/_next)?/static/(?:chunks|css|media)/[^"\']+\.(?:js|css))["\']', js["content"])
            for ref in refs:
                if ref.startswith("http"):
                    full = ref
                elif ref.startswith("/"):
                    full = base + ref
                elif ref.startswith("static/"):
                    # Next.js specific path
                    full = f"{base}/_next/{ref}"
                else:
                    full = f"{base}/{ref}"
                
                if full not in seen:
                    new_urls.add(full)

        from concurrent.futures import ThreadPoolExecutor, as_completed
        # Limit to 20 additional files
        urls_to_fetch = list(new_urls)[:20]
        if not urls_to_fetch:
            return

        def fetch_ref(url):
            resp = self._fetch(url, timeout=5)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                return {"url": url, "content": resp.text}
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(fetch_ref, u): u for u in urls_to_fetch}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    if result["url"].endswith(".css"):
                        self.css_contents.append(result)
                    else:
                        self.js_contents.append(result)

    def scan_wayback(self):
        """Query Wayback Machine CDX API to find historical JS secrets."""
        import json
        cdx_url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=timestamp,original&filter=mimetype:application/javascript&collapse=urlkey&limit=15"
        try:
            resp = self.session.get(cdx_url, timeout=30)
            if not resp or resp.status_code != 200:
                return {"wayback_error": f"Failed to reach CDX API: {getattr(resp, 'status_code', 'Timeout')}"}
            
            data = resp.json()
            if not data or len(data) <= 1:
                return {"wayback_files": 0}
            
            # Skip the first row (header row)
            archives = data[1:]
            
            from concurrent.futures import ThreadPoolExecutor, as_completed
            fetched_count = 0
            
            def fetch_archive(timestamp, original):
                archive_url = f"https://web.archive.org/web/{timestamp}id_/{original}"
                r = self.session.get(archive_url, timeout=20, allow_redirects=True)
                if r and r.status_code == 200 and len(r.text) > 50:
                    return {"url": f"[ARCHIVE] {original}", "content": r.text}
                return None
                
            with ThreadPoolExecutor(max_workers=5) as pool:
                futures = {pool.submit(fetch_archive, row[0], row[1]): row for row in archives}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        self.js_contents.append(result)
                        fetched_count += 1
            
            # Rebuild all_source to include the new historical files so scan_secrets can find them
            self.all_source = self.page_text
            for js in self.js_contents:
                self.all_source += "\n" + js["content"]
            for css in self.css_contents:
                self.all_source += "\n" + css["content"]
                
            return {"wayback_files_fetched": fetched_count}
        except Exception as e:
            return {"wayback_error": str(e)}

    def scan_secrets(self):
        if not self.all_source:
            self.all_source = self.page_text or ""
        findings = []

        # False positive exclusion patterns
        fp_contexts = [
            r"--token-",          # CSS custom properties like --token-UUID
            r"--color-",          # CSS custom properties
            r"--font-",           # CSS custom properties
            r"var\(--",           # CSS var() references
            r"csrf",              # CSRF tokens are expected
            r"nonce=",            # Content nonces are expected
            r"integrity=",        # SRI hashes
            r"data:image/",       # Data URIs
            r"sourceMappingURL",  # Source map URLs
            r"\.woff", r"\.ttf",  # Font files
            r"apbct-",            # CleanTalk spam plugin
            r"cleantalk",         # CleanTalk plugin
            r"poptin",            # Poptin popup plugin
        ]

        for name, pattern in SECRET_PATTERNS.items():
            matches = list(re.finditer(pattern, self.all_source))
            # Skip patterns with too many matches (likely false positives)
            if len(matches) > 50:
                continue
            for m in matches:
                val = m.group(0)
                ctx_start = max(0, m.start() - 80)
                ctx_end = min(len(self.all_source), m.end() + 80)
                context = self.all_source[ctx_start:ctx_end].replace("\n", " ").strip()

                # --- FALSE POSITIVE FILTERS ---
                # Skip CSS custom property tokens (--token-UUID, --tw-, etc.)
                if any(re.search(fp, context, re.IGNORECASE) for fp in fp_contexts):
                    continue

                # Skip IP addresses that look like version numbers (1.2.3.4 in semver context)
                if name == "IP Address (Private)":
                    if re.search(r'version|@\d|"\d+\.\d+\.\d+', context, re.IGNORECASE):
                        continue

                # Skip JWT/Supabase in non-secret contexts (CSS, font definitions, etc.)
                if name in ("JWT Token", "Supabase Key"):
                    if any(x in context.lower() for x in ["font", "stylesheet", "css", "woff", "image"]):
                        continue

                # Skip Google API keys that are clearly example/placeholder
                if name == "Google API Key":
                    if any(x in val for x in ["EXAMPLE", "YOUR_API", "REPLACE"]):
                        continue

                # Filter i18n/translation strings for Generic Secret
                # Real secrets are alphanumeric with special chars, not natural language
                if name == "Generic Secret":
                    val_only = m.group(1) if m.lastindex else val
                    i18n_values = [
                        "mot de passe", "nouveau mot de passe", "mot de passe actuel",
                        "confirm password", "current password", "new password",
                        "change password", "forgot password", "cancel",
                        "passworddesc", "password description",
                        "contraseña", "contraseña actual", "nueva contraseña",
                        "confirmar contraseña", "cambiar contraseña",
                        "email", "correo", "correo electrónico",
                        "usuario", "nombre de usuario",
                    ]
                    # Skip if the value looks like i18n (contains known i18n strings)
                    val_lower = val_only.lower() if val_only else ""
                    if any(i18n in val_lower for i18n in i18n_values):
                        continue

                    # Skip common JS/UI patterns that are NOT secrets
                    # e.access_token="access_token" (key assignment to string)
                    # password:"label", passwordDesc:"description" (i18n labels)
                    # URL filtering placeholders: password="%filtered%", username="%filtered%"
                    if re.search(r'\baccess_token["\']?\s*=\s*["\']access_token["\']', context):
                        continue
                    if re.search(r'password["\']?\s*:\s*["\'][^"\']{1,30}["\']', context):
                        continue
                    if re.search(r'(password|username)\s*=\s*["\']%filtered%["\']', context, re.IGNORECASE):
                        continue

                # Skip Statsig client API keys in JS bundles (legitimate, not secret)
                if name == "Generic Secret" and "statsigClientApiKey" in context:
                    continue

                # Skip when the value looks like a dedicated secret type (Google AIza, OpenAI sk-, etc.)
                # These are already caught as Google API Key / OpenAI Key separately
                if name == "Generic Secret":
                    if re.search(r'\bapiKey["\']?\s*:\s*["\'][A-Za-z0-9_-]{20,}', context):
                        continue

                # Skip API_KEY / ApiKey enum values: "invalid_api_key", "enterprise_admin_api_key"
                # These are TypeScript enum/string constants, not real credentials
                if name == "Generic Secret":
                    if re.search(r'\b(API_KEY|ApiKey)\s*=\s*"[^"]*_key"', context, re.IGNORECASE):
                        continue

                # Skip URL filtering placeholders: password="%filtered%", username="%filtered%"
                if name == "Generic Secret":
                    if '"%filtered%"' in context or "'%filtered%'" in context:
                        continue

                # Skip i18n label keys: ForgotPassword="forgot-password", RESET_PASSWORD="/reset-password"
                if name == "Generic Secret":
                    if re.search(r'(FORGOT_PASSWORD|Password)\s*=\s*"[^"]*"', context, re.IGNORECASE):
                        continue
                    if re.search(r'\bRESET_PASSWORD\s*=\s*"[^"]*"', context, re.IGNORECASE):
                        continue
                    # Skip ApiKey="invalid_api_key", API_KEY="site_role_in_product_mcp_api_key" — these are enum error codes
                    if re.search(r'(ApiKey|API_KEY)\s*=\s*"\w+_\w+"', context, re.IGNORECASE):
                        continue

                loc = "HTML page"
                for js in self.js_contents:
                    if val in js["content"]:
                        loc = js["url"]
                        break
                for css in self.css_contents:
                    if val in css["content"]:
                        loc = css["url"]
                        break
                masked = val[:12] + "..." + val[-6:] if len(val) > 20 else val[:6] + "****"
                findings.append({"type": name, "value_masked": masked, "location": loc, "context": context[:150], "severity": self._secret_severity(name)})
        seen = set()
        unique = []
        for f in findings:
            key = f"{f['type']}:{f['value_masked']}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return {"secrets": unique}

    def _secret_severity(self, name):
        critical = ["AWS Access Key", "AWS Secret Key", "Stripe Secret Key", "OpenAI API Key", "Anthropic API Key", "OpenRouter API Key", "RSA Private Key", "SSH Private Key", "Database URL", "Generic Secret"]
        high = ["Google API Key", "GitHub Token", "Slack Token", "SendGrid API Key", "Discord Bot Token", "Supabase Key", "JWT Token", "PGP Private Key"]
        if name in critical:
            return "CRITICAL"
        if name in high:
            return "HIGH"
        return "MEDIUM"

    def scan_sensitive_paths(self):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        findings = []
        base = f"{self.parsed.scheme}://{self.parsed.netloc}"

        def probe(path):
            try:
                r = requests.get(base + path, timeout=2, allow_redirects=False, headers={"User-Agent": UA})
                if r.status_code == 200 and len(r.text) > 10:
                    text = r.text
                    # Verify actual content type (not Cloudflare/WAF HTML block page)
                    content_type = r.headers.get("Content-Type", "")
                    # Cloudflare/WAF often returns HTML for blocked paths
                    is_html_blocked = (
                        text.strip().startswith("<!DOCTYPE html>") or
                        text.strip().startswith("<html") or
                        "text/html" in content_type.lower()
                    )
                    if is_html_blocked:
                        return None
                    # For sensitive paths, verify content matches expected format
                    if ".git/HEAD" in path:
                        # Valid git HEAD: contains "ref: refs/heads/" or 40-char commit hash
                        if not (re.search(r"ref:\s+refs/", text) or re.match(r"[0-9a-f]{40}", text.strip())):
                            return None
                    elif ".ssh/id_" in path:
                        # Valid SSH key: starts with -----BEGIN
                        if not text.strip().startswith("-----BEGIN"):
                            return None
                    is_html_error = any(x in text.lower() for x in ["404", "not found", "page not found", "error"])
                    if not is_html_error:
                        snippet = text[:200].replace("\n", " ").strip()
                        if any(x in path for x in [".env", ".git", "config", "wp-config", "backup", ".ssh"]):
                            sev = "CRITICAL"
                        elif any(x in path for x in ["package.json", "docker", "composer"]):
                            sev = "HIGH"
                        elif any(x in path for x in ["robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt"]):
                            sev = "INFO"
                        else:
                            sev = "MEDIUM"
                        return {"path": path, "status": r.status_code, "size": len(text), "snippet": snippet, "severity": sev}
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=15) as pool:
            futures = {pool.submit(probe, p): p for p in SENSITIVE_PATHS}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    findings.append(r)
        return {"sensitive_paths": findings}

    def scan_cookies(self):
        if not self.response:
            return {}
        cookies = []
        for c in self.session.cookies:
            flags = {"secure": c.secure, "httponly": "httponly" in str(c._rest).lower() or c.has_nonstandard_attr("HttpOnly"), "samesite": c.get_nonstandard_attr("SameSite") or "Not Set"}
            issues = []
            if not c.secure:
                if self.parsed.scheme == "https":
                    issues.append("[INFO] Missing Secure flag — (Cookie sent over HTTPS anyway, but flag is missing)")
                else:
                    issues.append("Missing Secure flag — cookie sent over HTTP")
            if not flags["httponly"]:
                issues.append("[INFO] Missing HttpOnly flag — accessible via JS (Vulnerable only if XSS exists)")
            if flags["samesite"] == "Not Set":
                issues.append("[INFO] Missing SameSite flag — (Modern browsers default to Lax)")
            cookies.append({"name": c.name, "domain": c.domain, "path": c.path, "secure": c.secure, "httponly": flags["httponly"], "samesite": flags["samesite"], "issues": issues})
        return {"cookies": cookies}

    def scan_forms(self):
        if not self.soup:
            return {}
        forms = []
        for f in self.soup.find_all("form"):
            action = f.get("action", "")
            method = f.get("method", "GET").upper()
            inputs = [{"name": i.get("name", ""), "type": i.get("type", "text"), "id": i.get("id", "")} for i in f.find_all("input")]
            has_csrf = any(i.get("type") == "hidden" and any(x in (i.get("name","")).lower() for x in ["csrf", "token", "_token", "xsrf"]) for i in f.find_all("input"))
            has_password = any(i.get("type") == "password" for i in f.find_all("input"))
            issues = []
            if not has_csrf:
                if method == "GET" and (not action or action == "#"):
                    pass # Vibe-Sec: GET forms without action are usually client-side search/filters, CSRF not applicable
                elif method == "GET":
                    issues.append("[INFO] No CSRF token — but form uses GET (usually safe if it doesn't change state)")
                else:
                    issues.append("No CSRF token detected — vulnerable to Cross-Site Request Forgery")
            if method == "GET" and has_password:
                issues.append("Password sent via GET — credentials visible in URL and logs")
            if action.startswith("http://"):
                issues.append("Form submits over HTTP — credentials sent in plaintext")
            if not action or action == "#":
                issues.append("[INFO] Empty/anchor form action — typically client-side UI (React/Vue/Framer)")
            
            # Only add to report if there are non-INFO issues or we want to show INFO
            if issues:
                forms.append({"action": action or "(empty)", "method": method, "inputs": inputs, "has_csrf": has_csrf, "issues": issues})
        return {"forms": forms}

    def scan_info_leaks(self):
        if not self.soup:
            return {}
        leaks = []
        comments = self.soup.find_all(string=lambda t: isinstance(t, type(self.soup.find_all(string=True)[0])) and t.strip().startswith("<!--") if self.soup.find_all(string=True) else False)
        import re as re2
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for m in comment_pattern.finditer(self.page_text):
            c = m.group(1).strip()
            if len(c) > 5 and not c.startswith("[if"):
                suspicious = ["todo", "fixme", "hack", "bug", "password", "secret", "key", "token", "api", "debug", "temp", "remove"]
                if any(s in c.lower() for s in suspicious):
                    leaks.append({"type": "Suspicious HTML Comment", "content": c[:150], "severity": "MEDIUM"})
        sm = re.findall(r'//[#@]\s*sourceMappingURL=(\S+)', self.all_source or self.page_text)
        for s in sm:
            leaks.append({"type": "Source Map Exposed", "content": s, "severity": "HIGH"})
        err_patterns = [r"(?i)stack\s*trace", r"(?i)traceback\s*\(most recent", r"(?i)fatal\s+error", r"(?i)uncaught\s+exception", r"(?i)syntax\s+error.*?line\s+\d+"]
        for p in err_patterns:
            if re.search(p, self.page_text):
                leaks.append({"type": "Error/Debug Info Exposed", "content": re.search(p, self.page_text).group(0), "severity": "HIGH"})

        # --- Framework runtime config exposure (Nuxt, Next.js, etc.) ---
        leaks += self._scan_framework_config_exposure()

        return {"info_leaks": leaks}

    def _scan_framework_config_exposure(self):
        """Detect exposed framework runtime configs: __NUXT__, __NEXT_DATA__, __NUXT_DATA__, etc."""
        leaks = []

        # Patterns to find framework config objects embedded in HTML
        framework_patterns = [
            ("Nuxt.js Runtime Config",  r'window\.__NUXT__\s*=\s*(\{.{20,}?\})',          re.DOTALL),
            ("Nuxt.js SSR Data",        r'<script[^>]+id=["\']__NUXT_DATA__["\'][^>]*>([\s\S]{20,}?)</script>', re.IGNORECASE | re.DOTALL),
            ("Next.js Build Data",      r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>([\s\S]{20,}?)</script>', re.IGNORECASE | re.DOTALL),
        ]

        # Sensitive keys to extract from the config blobs
        sensitive_keys = [
            ("baseUrl", "MEDIUM"),
            ("serverBaseUrl", "MEDIUM"),
            ("newBaseURL", "MEDIUM"),
            ("buildId", "INFO"),
            ("NODE_ENV", "INFO"),
            ("STRIPE_PMC_KEY_LIVE", "HIGH"),
            ("STRIPE_PMC_KEY_TEST", "MEDIUM"),
            ("STRIPE_BNPL_CONFIGURATION_LIVE", "HIGH"),
            ("STRIPE_DEFAULT_CONFIGURATION_LIVE", "HIGH"),
            ("ENTERPRISE_RECAPTCHA_SITE_KEY", "MEDIUM"),
            ("RECAPTCHA_SITE_KEY", "MEDIUM"),
            ("HLS_URL", "LOW"),
            ("REST_API_URLS", "MEDIUM"),
            ("STATS_API_URL", "MEDIUM"),
            ("paymentsServiceUrl", "MEDIUM"),
            ("cdnURL", "INFO"),
        ]

        for label, pattern, flags in framework_patterns:
            m = re.search(pattern, self.page_text, flags)
            if not m:
                continue

            blob = m.group(1)[:5000]  # Limit to first 5000 chars to avoid huge dumps
            summary_parts = []

            for key, sev in sensitive_keys:
                # Match  "key":"value"  or  key:"value"  or  "key":"value"
                val_m = re.search(rf'["\']?{re.escape(key)}["\']?\s*:\s*["\']([^"\'{{}}]+)["\']', blob)
                if val_m:
                    val = val_m.group(1).strip()
                    summary_parts.append(f"{key}={val}")

            if summary_parts:
                # Report each HIGH/CRITICAL key individually
                for key, sev in sensitive_keys:
                    val_m = re.search(rf'["\']?{re.escape(key)}["\']?\s*:\s*["\']([^"\'{{}}]+)["\']', blob)
                    if val_m and sev in ("HIGH", "CRITICAL"):
                        val = val_m.group(1).strip()
                        leaks.append({
                            "type": f"Framework Config Leak — {label}",
                            "content": f"{key}: {val}",
                            "severity": sev
                        })

                # Also report a summary entry with all found keys
                leaks.append({
                    "type": f"Framework Config Exposed — {label}",
                    "content": ("Runtime config object injected in HTML exposes: "
                                + " | ".join(summary_parts[:10])),
                    "severity": "MEDIUM"
                })

        return leaks

    def scan_js_deep(self):
        if not self.js_contents:
            return {}
        findings = []
        for js in self.js_contents:
            c = js["content"]
            src = js["url"]
            dangerous = [("eval(", "Use of eval() — potential code injection"), ("document.write(", "document.write() — potential DOM XSS"), ("innerHTML", "innerHTML assignment — potential XSS"), (".innerText=", None), ("setTimeout(String", "setTimeout with string — potential injection"), ("setInterval(String", "setInterval with string — potential injection"), ("location.href=", "Unvalidated redirect — potential open redirect"), ("window.location=", "Unvalidated redirect — potential open redirect"), ("document.cookie", "Direct cookie access in JS"), ("localStorage.", "LocalStorage usage — check for sensitive data"), ("sessionStorage.", "SessionStorage usage — check for sensitive data"), ("postMessage(", "postMessage — check origin validation")]
            for pattern, desc in dangerous:
                if desc and pattern in c:
                    idx = c.index(pattern)
                    ctx = c[max(0,idx-40):idx+len(pattern)+40].replace("\n"," ").strip()
                    findings.append({"pattern": pattern, "description": desc, "source": src, "context": ctx[:120], "severity": "MEDIUM"})
            fetch_urls = re.findall(r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]', c)
            xhr_urls = re.findall(r'\.open\s*\(\s*[\'"][A-Z]+[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]', c)
            for u in fetch_urls + xhr_urls:
                if u.startswith("http"):
                    findings.append({"pattern": "API Endpoint", "description": f"External API call: {u[:80]}", "source": src, "context": u, "severity": "INFO"})
        seen = set()
        unique = []
        for f in findings:
            k = f"{f['pattern']}:{f['source']}"
            if k not in seen:
                seen.add(k)
                unique.append(f)
        return {"js_analysis": unique[:50]}

    def scan_wpscan(self):
        """Run WPScan if WordPress is detected using Docker."""
        if not self.wordpress_detected:
            return {"wpscan": []}

        import subprocess
        import json
        import os
        from dotenv import load_dotenv

        # Load .env file
        load_dotenv()
        wpscan_token = os.getenv("WPSCAN_API_TOKEN", "").strip()

        # Check if Docker is available
        try:
            subprocess.run(["docker", "--version"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return {"wpscan": [{"name": "Docker Not Available", "severity": "INFO", "description": "Install Docker to run WPScan automatically", "url": self.url, "type": "install_error"}]}

        findings = []
        # Pull image if needed (silent)
        subprocess.run(["docker", "pull", "wpscanteam/wpscan"], capture_output=True, timeout=60)

        cmd = [
            "docker", "run", "--rm",
            "-e", f"WPSCAN_TOKEN={wpscan_token}",
            "wpscanteam/wpscan",
            "--url", self.url,
            "--format", "json",
            "--no-update",
            "--max-threads", "5",
            "--random-user-agent"
        ]

        if wpscan_token:
            cmd.append("--api-token")
            cmd.append(wpscan_token)

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            try:
                # Parse each line as separate JSON object
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if "target" in data:
                                for vuln in data.get("vulnerabilities", []):
                                    findings.append({
                                        "name": vuln.get("title", "Unknown"),
                                        "severity": "HIGH",
                                        "description": f"{vuln.get('description', '')} | Ref: {vuln.get('references', {}).get('url', ['N/A'])[0]}",
                                        "url": self.url,
                                        "type": "wordpress_vuln"
                                    })
                                for plugin_name, plugin_data in data.get("plugins", {}).items():
                                    if plugin_data.get("vulnerabilities"):
                                        for v in plugin_data["vulnerabilities"]:
                                            findings.append({
                                                "name": f"Plugin: {plugin_name} - {v.get('title', 'vuln')}",
                                                "severity": "HIGH",
                                                "description": v.get("description", ""),
                                                "url": self.url,
                                                "type": "plugin_vuln"
                                            })
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

            if not findings:
                if result.returncode == 0:
                    findings.append({
                        "name": "WordPress Site Scanned",
                        "severity": "INFO",
                        "description": "WordPress detected but no vulnerabilities found with current configuration.",
                        "url": self.url,
                        "type": "wordpress_clean"
                    })
        except subprocess.TimeoutExpired:
            findings.append({"name": "WPScan Timeout", "severity": "INFO", "description": "WPScan timed out after 3 minutes", "url": self.url, "type": "timeout"})
        except Exception:
            pass

        return {"wpscan": findings}

    def scan_gitleaks(self):
        """Run gitleaks if GitHub repository is detected, auto-installing if needed."""
        if not self.github_detected:
            return {"gitleaks": []}

        import subprocess
        import json
        import re

        # Auto-install gitleaks if not present
        try:
            subprocess.run(["which", "gitleaks"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            self.console.print("[yellow]Gitleaks not found. Installing...[/yellow]")
            install_cmd = ["go", "install", "github.com/gitleaks/gitleaks/v8@latest"]
            try:
                result = subprocess.run(["go", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode != 0:
                    # Try binary download
                    import urllib.request
                    import zipfile
                    import os
                    bin_dir = os.path.expanduser("~/.local/bin")
                    os.makedirs(bin_dir, exist_ok=True)
                    VERSION = "8.18.2"
                    URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks-darwin-arm64.zip"
                    # Detect OS
                    if platform.system() == "Linux":
                        if platform.machine() == "x86_64":
                            URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks-linux-amd64.zip"
                        else:
                            URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/gitleaks-linux-arm64.zip"
                    try:
                        urllib.request.urlretrieve(URL, "/tmp/gitleaks.zip")
                        with zipfile.ZipFile("/tmp/gitleaks.zip") as z:
                            z.extractall(bin_dir)
                        os.chmod(f"{bin_dir}/gitleaks", 0o755)
                    except Exception:
                        pass
            except Exception:
                pass

        # Find GitHub repo URL from the scanned site
        github_repos = re.findall(r"github\.com/[\w-]+/[\w.-]+", self.all_source or self.page_text)
        findings = []

        for repo_url in set(github_repos)[:3]:  # Limit to 3 repos
            repo = repo_url.replace("github.com/", "")
            clone_url = f"https://github.com/{repo}"
            # Try to scan public repo with gitleaks via git ls-remote
            cmd = ["git", "ls-remote", clone_url]
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
                if result.returncode == 0:
                    # Clone and scan
                    import tempfile
                    with tempfile.TemporaryDirectory() as tmpdir:
                        clone_cmd = ["git", "clone", "--depth", "1", clone_url, tmpdir]
                        clone_result = subprocess.run(clone_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                        if clone_result.returncode == 0:
                            scan_cmd = ["gitleaks", "detect", "--source", tmpdir, "--format", "json"]
                            scan_result = subprocess.run(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
                            if scan_result.stdout:
                                try:
                                    leaks = json.loads(scan_result.stdout)
                                    for leak in leaks:
                                        findings.append({
                                            "name": leak.get("RuleID", "Secret Found"),
                                            "severity": "CRITICAL",
                                            "description": f"File: {leak.get('File', 'unknown')}, Line: {leak.get('StartLine', '?')}",
                                            "url": clone_url,
                                            "type": "exposed_secret"
                                        })
                                except json.JSONDecodeError:
                                    pass
            except Exception:
                pass

        if not findings and self.github_detected:
            findings.append({
                "name": "GitHub Repository Detected",
                "severity": "INFO",
                "description": f"GitHub repo detected: {repo_url}. Provide GitHub token for full scan.",
                "url": clone_url if 'clone_url' in locals() else self.url,
                "type": "github_detected"
            })

        return {"gitleaks": findings}

    def scan_api_endpoints(self):
        """Actively probe for Swagger files and GraphQL endpoints to analyze API security."""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        findings = []
        base = f"{self.parsed.scheme}://{self.parsed.netloc}"
        
        # 1. Probe for Swagger / OpenAPI JSON schemas
        swagger_paths = [
            "/swagger.json", "/api/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
            "/openapi.json", "/api/openapi.json", "/v3/api-docs", "/api-docs", "/v2/api-docs"
        ]
        
        def probe_swagger(path):
            try:
                r = requests.get(base + path, timeout=3, allow_redirects=False, headers={"User-Agent": UA})
                if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
                    data = r.json()
                    # Verify it's actually swagger/openapi
                    if "swagger" in data or "openapi" in data:
                        title = data.get("info", {}).get("title", "Unknown API")
                        version = data.get("info", {}).get("version", "1.0")
                        paths = data.get("paths", {})
                        endpoints_count = len(paths)
                        
                        # Check for authentication
                        has_auth = "securityDefinitions" in data or "securitySchemes" in data.get("components", {})
                        
                        sev = "HIGH" if not has_auth else "MEDIUM"
                        desc = (f"Swagger/OpenAPI schema exposed.\n"
                                f"API Title: {title} (v{version})\n"
                                f"Endpoints Exposed: {endpoints_count}\n"
                                f"Authentication Defined: {'Yes' if has_auth else 'NO (Unauthenticated API)'}")
                                
                        return {"type": "Swagger Schema", "url": base + path, "description": desc, "severity": sev}
            except:
                pass
            return None
            
        # 2. Probe for GraphQL Introspection
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/api/v1/graphql"]
        introspection_query = {"query": "{ __schema { queryType { name } } }"}
        
        def probe_graphql(path):
            try:
                r = requests.post(base + path, json=introspection_query, timeout=3, allow_redirects=False, headers={"User-Agent": UA})
                if r.status_code == 200:
                    data = r.json()
                    if "data" in data and "__schema" in data["data"]:
                        desc = ("GraphQL Introspection is ENABLED! The entire database schema can be dumped.\n"
                                f"Exploit: curl -X POST {base+path} -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'")
                        return {"type": "GraphQL Introspection", "url": base + path, "description": desc, "severity": "CRITICAL"}
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(probe_swagger, p) for p in swagger_paths]
            futures += [pool.submit(probe_graphql, p) for p in graphql_paths]
            
            for f in as_completed(futures):
                r = f.result()
                if r:
                    findings.append(r)
                    
        return {"api_discovery": findings}
