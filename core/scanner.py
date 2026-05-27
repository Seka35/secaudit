"""Core scanner engine for SecAudit."""
import re, ssl, socket, hashlib, json, time
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

    def _fetch(self, url, timeout=10):
        try:
            return self.session.get(url, timeout=timeout, allow_redirects=True)
        except:
            return None

    def run_full_scan(self):
        results = {}
        modules = [
            ("Fetching page", self.fetch_page),
            ("Analyzing DNS & domain", self.scan_domain),
            ("Analyzing HTTP headers", self.scan_headers),
            ("Analyzing SSL/TLS", self.scan_ssl),
            ("Detecting technology stack", self.scan_tech),
            ("Detecting vibe-coding tools", self.scan_vibe_coding),
            ("Crawling linked resources", self.crawl_resources),
            ("Hunting historical secrets (Wayback OSINT)", self.scan_wayback),
            ("Scanning for secrets", self.scan_secrets),
            ("Checking sensitive paths", self.scan_sensitive_paths),
            ("Analyzing cookies", self.scan_cookies),
            ("Analyzing forms", self.scan_forms),
            ("Checking for info leaks", self.scan_info_leaks),
            ("Analyzing JavaScript", self.scan_js_deep),
            ("Probing API & GraphQL endpoints", self.scan_api_endpoints),
            ("Running Nuclei engine (Infrastructure vulnerabilities)", self.scan_nuclei),
        ]
        with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), console=self.console) as prog:
            for desc, fn in modules:
                t = prog.add_task(desc, total=None)
                try:
                    r = fn()
                    if r:
                        results.update(r)
                except Exception as e:
                    results[desc] = {"error": str(e)}
                prog.update(t, completed=True)
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
                    break
        meta = {}
        if self.soup:
            gen = self.soup.find("meta", attrs={"name": "generator"})
            if gen:
                meta["generator"] = gen.get("content", "")
            for m in self.soup.find_all("meta"):
                name = m.get("name", m.get("property", ""))
                if name:
                    meta[name] = m.get("content", "")
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
                    is_html_error = any(x in r.text.lower() for x in ["404", "not found", "page not found", "error"])
                    if not is_html_error:
                        snippet = r.text[:200].replace("\n", " ").strip()
                        sev = "CRITICAL" if any(x in path for x in [".env", ".git", "config", "wp-config", "backup", ".ssh"]) else "HIGH" if any(x in path for x in ["package.json", "docker", "composer"]) else "MEDIUM"
                        return {"path": path, "status": r.status_code, "size": len(r.text), "snippet": snippet, "severity": sev}
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
                issues.append("Missing Secure flag — cookie sent over HTTP")
            if not flags["httponly"]:
                issues.append("Missing HttpOnly flag — accessible via JavaScript (XSS risk)")
            if flags["samesite"] == "Not Set":
                issues.append("Missing SameSite — vulnerable to CSRF")
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
                issues.append("No CSRF token detected — vulnerable to Cross-Site Request Forgery")
            if method == "GET" and has_password:
                issues.append("Password sent via GET — credentials visible in URL and logs")
            if action.startswith("http://"):
                issues.append("Form submits over HTTP — credentials sent in plaintext")
            if not action or action == "#":
                issues.append("Empty/anchor form action — may indicate client-side only handling")
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
        return {"info_leaks": leaks}

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

    def scan_nuclei(self):
        """Run Nuclei in the background for infrastructure CVEs, exposed panels, and misconfigurations."""
        import subprocess
        import json
        
        # Check if nuclei is installed
        try:
            subprocess.run(["which", "nuclei"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            return {"nuclei": []} # Not installed
            
        findings = []
        # Run targeted nuclei scan
        cmd = ["nuclei", "-u", self.url, "-tags", "cve,exposure,misconfig,vuln", "-jsonl", "-silent"]
        try:
            # We use timeout=180 to avoid hanging forever on slow targets
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    finding = {
                        "name": info.get("name", "Unknown Vulnerability"),
                        "severity": info.get("severity", "info").upper(),
                        "description": info.get("description", ""),
                        "url": data.get("matched-at", self.url),
                        "type": data.get("type", "unknown")
                    }
                    findings.append(finding)
                except:
                    pass
        except subprocess.TimeoutExpired:
            findings.append({
                "name": "Nuclei Scan Timeout",
                "severity": "INFO",
                "description": "The Nuclei scan timed out after 3 minutes.",
                "url": self.url,
                "type": "timeout"
            })
        except Exception as e:
            pass
            
        return {"nuclei": findings}

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
