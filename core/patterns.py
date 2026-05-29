"""Secret detection patterns for SecAudit."""

SECRET_PATTERNS = {
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Google OAuth Token": r"\bya29\.[0-9A-Za-z\-_]+\b",
    "Stripe Secret Key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Publishable Key": r"\bpk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe Test Secret": r"\bsk_test_[0-9a-zA-Z]{24,}\b",
    "OpenAI API Key": r"\bsk-[a-zA-Z0-9]{32,}\b",
    "Anthropic API Key": r"\bsk-ant-[a-zA-Z0-9\-]{36,}\b",
    "OpenRouter API Key": r"\bsk-or-v1-[a-zA-Z0-9]{48,}\b",
    "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b",
    "GitHub OAuth": r"\bgho_[A-Za-z0-9]{36,}\b",
    "GitLab Token": r"\bglpat-[A-Za-z0-9\-]{20,}\b",
    "Slack Token": r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+",
    "Discord Bot Token": r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b",
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "Twilio Account SID": r"\bAC[0-9a-fA-F]{32}\b",
    "SendGrid API Key": r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b",
    "Mailgun API Key": r"\bkey-[0-9a-zA-Z]{32}\b",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key": r"(?i)firebase.*?['\"]AIza[0-9A-Za-z\-_]{35}['\"]",
    "Heroku API Key": r"(?i)(?:heroku|HEROKU)[_\s]*(?:api[_\s]*)?(?:key|token|secret)\s*[=:]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
    "Supabase Key": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Generic Secret": r"(?i)(?:secret_key|password|passwd|api_key|apikey|api-key|auth_token|access_token|private_key|client_secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    "Database URL": r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'\"<>]+",
    "IP Address (Private)": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "Base64 Encoded Secret": r"(?i)(?:secret|password|key|token)\s*[=:]\s*['\"]?(?:[A-Za-z0-9+/]{40,}={0,2})['\"]?",
    "Vercel Token": r"(?i)vercel[_\-]?(?:token|key)\s*[=:]\s*['\"]?[\w\-]{20,}['\"]?",
    "Netlify Token": r"(?i)netlify[_\-]?(?:token|key)\s*[=:]\s*['\"]?[\w\-]{20,}['\"]?",
    "Shopify API": r"(?i)\bshpat_[a-fA-F0-9]{32}\b",
    "Cloudflare API": r"(?i)cloudflare.*?['\"][\w\-]{37,}['\"]",
    "DigitalOcean Token": r"\bdop_v1_[a-f0-9]{64}\b",
    "Mapbox Token": r"pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Square Access Token": r"\bsq0atp-[0-9A-Za-z\-_]{22}\b",
    "PayPal Client ID": r"(?i)paypal.*?client.?id\s*[=:]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",
}


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "expected": True,
        "severity": "HIGH",
        "description": "Enforces HTTPS connections, preventing SSL stripping attacks.",
        "exploit": "Without HSTS, an attacker on the same network can intercept the initial HTTP request and perform a man-in-the-middle attack using SSL stripping (e.g., with tools like sslstrip).",
        "patch": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "expected": True,
        "severity": "HIGH",
        "description": "Prevents XSS, clickjacking, and other code injection attacks.",
        "exploit": "Without CSP, an attacker can inject malicious scripts via XSS vulnerabilities. Any user input reflected in the page could execute arbitrary JavaScript.",
        "patch": "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
    },
    "X-Content-Type-Options": {
        "expected": True,
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing attacks.",
        "exploit": "Without this header, browsers may interpret files as a different MIME type, allowing an attacker to upload a disguised file (e.g., HTML as image) that gets executed.",
        "patch": "Add header: X-Content-Type-Options: nosniff"
    },
    "X-Frame-Options": {
        "expected": True,
        "severity": "INFO",
        "description": "Prevents clickjacking attacks by controlling iframe embedding.",
        "exploit": "Vibe-Sec: Most modern browsers handle this via CSP. (Clickjacking is rarely fully exploitable via automated scanners).",
        "patch": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed)"
    },
    "X-XSS-Protection": {
        "expected": True,
        "severity": "INFO",
        "description": "Legacy XSS filter (deprecated but still useful for older browsers).",
        "exploit": "Vibe-Sec: Deprecated in modern browsers. CSP is the modern standard.",
        "patch": "Add header: X-XSS-Protection: 1; mode=block"
    },
    "Referrer-Policy": {
        "expected": True,
        "severity": "INFO",
        "description": "Controls how much referrer information is sent with requests.",
        "exploit": "Vibe-Sec: Good practice, but not directly exploitable unless sensitive tokens are in URLs (which shouldn't happen).",
        "patch": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "expected": True,
        "severity": "INFO",
        "description": "Controls which browser features the site can use.",
        "exploit": "Vibe-Sec: Modern browsers sandbox APIs anyway. Good defense-in-depth, but missing it is rarely critical.",
        "patch": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
}

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.git/config", "/.git/HEAD",
    "/.svn/entries",
    "/wp-config.php", "/wp-config.php.bak",
    "/config.php", "/configuration.php",
    "/.htaccess", "/.htpasswd",
    "/web.config",
    "/phpinfo.php",
    "/server-status", "/server-info",
    "/.DS_Store",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml",
    "/.well-known/security.txt",
    "/package.json", "/package-lock.json",
    "/composer.json", "/composer.lock",
    "/Gemfile", "/Gemfile.lock",
    "/Dockerfile", "/docker-compose.yml",
    "/.dockerignore",
    "/.gitignore",
    "/next.config.js", "/next.config.mjs",
    "/vite.config.js", "/vite.config.ts",
    "/nuxt.config.js", "/nuxt.config.ts",
    "/tsconfig.json", "/jsconfig.json",
    "/vercel.json", "/netlify.toml",
    "/firebase.json", "/.firebaserc",
    "/swagger.json", "/api-docs",
    "/graphql", "/.graphql",
    "/debug", "/trace",
    "/admin", "/administrator",
    "/backup.sql", "/dump.sql", "/database.sql",
    "/error.log", "/access.log", "/debug.log",
    "/.bash_history", "/.ssh/id_rsa",
    "/api/v1", "/api/v2",
    "/health", "/healthcheck", "/status",
    "/_next/static/", "/static/js/",
    "/source-map", "/.map",
    "/webpack.config.js",
]

TECH_SIGNATURES = {
    "React": [r"react(?:\.min)?\.js", r"__NEXT_DATA__", r"_react", r"reactDOM", r"data-reactroot", r"data-reactid"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static", r"next/dist", r"nextjs"],
    "Vue.js": [r"vue(?:\.min)?\.js", r"__vue__", r"v-bind", r"v-if", r"v-for", r"Vue\."],
    "Nuxt.js": [r"__NUXT__", r"nuxt", r"_nuxt/"],
    "Angular": [r"angular(?:\.min)?\.js", r"ng-app", r"ng-controller", r"ng-model", r"\[ngClass\]"],
    "Svelte": [r"svelte", r"__svelte"],
    "jQuery": [r"jquery(?:\.min)?\.js", r"\$\(document\)", r"\$\(function"],
    "Bootstrap": [r"bootstrap(?:\.min)?\.(?:js|css)", r"class=\".*?(?:container|row|col-)", r"btn btn-"],
    "Tailwind CSS": [r"tailwindcss", r"tailwind\.config", r"class=\".*?(?:flex|grid|text-|bg-|p-|m-|w-|h-)"],
    "WordPress": [r"wp-content", r"wp-includes", r"wp-json", r"wordpress"],
    "Django": [r"csrfmiddlewaretoken", r"django", r"__django"],
    "Laravel": [r"laravel", r"_token", r"csrf-token.*?content"],
    "Express.js": [r"X-Powered-By.*?Express"],
    "Flask": [r"Werkzeug", r"flask"],
    "Ruby on Rails": [r"X-Powered-By.*?Phusion", r"csrf-token", r"rails", r"turbolinks"],
    "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp\.net", r"X-AspNet-Version"],
    "PHP": [r"X-Powered-By.*?PHP", r"\.php", r"PHPSESSID"],
    "Cloudflare": [r"cf-ray", r"cloudflare", r"__cfduid"],
    "Vercel": [r"x-vercel", r"vercel", r"\.vercel\.app"],
    "Netlify": [r"x-nf-request-id", r"netlify"],
    "Firebase": [r"firebaseapp\.com", r"firebase\.js", r"firebaseio\.com"],
    "Supabase": [r"supabase", r"\.supabase\.co"],
    "Stripe.js": [r"js\.stripe\.com", r"stripe(?:\.min)?\.js", r"Stripe\("],
    "Google Analytics": [r"google-analytics\.com", r"gtag\(", r"GoogleAnalyticsObject", r"UA-\d{4,}-\d{1,}"],
    "Google Tag Manager": [r"googletagmanager\.com", r"GTM-[A-Z0-9]+"],
    "Hotjar": [r"hotjar\.com", r"_hjSettings"],
    "Sentry": [r"sentry\.io", r"Sentry\.init", r"@sentry"],
    "Webpack": [r"webpackJsonp", r"__webpack_require__", r"webpack"],
    "Vite": [r"@vite", r"vite/client", r"import\.meta\.env"],
}

# ============================================================================
# VIBE-CODING / AI BUILDER TOOL DETECTION
# Signatures left by AI-assisted coding platforms and no-code/low-code builders
# ============================================================================
VIBE_CODING_SIGNATURES = {
    "Replit": {
        "patterns": [
            r"replit\.dev", r"repl\.co", r"\.repl\.co",
            r"replit-badge", r"replit\.com",
            r"x-replit", r"__replit",
            r"replit-dev-domain", r"pid1\.replit",
            r"replitusercontent\.com",
        ],
        "description": "Replit — Cloud IDE with AI-assisted coding (Replit Agent / Ghostwriter)",
        "risk": "Replit deployments often expose .replit config, may have default CORS policies, and AI-generated code frequently contains hardcoded secrets or insecure patterns.",
    },
    "Lovable (GPT Engineer)": {
        "patterns": [
            r"lovable\.dev", r"lovable\.app",
            r"gptengineer\.app", r"gptengineer",
            r"Built with Lovable", r"built-with-lovable",
            r"data-lovable", r"lovableproject",
            r"\.lovable\.", r"lovable-tagger",
        ],
        "description": "Lovable (formerly GPT Engineer) — AI full-stack app builder",
        "risk": "Lovable apps often ship with exposed Supabase keys, default auth configs, and AI-generated code that may lack input validation or proper error handling.",
    },
    "Bolt.new": {
        "patterns": [
            r"bolt\.new", r"stackblitz\.com",
            r"bolt-generated", r"webcontainer",
            r"built.with" r"bolt",
        ],
        "description": "Bolt.new (StackBlitz) — AI-powered full-stack web app builder",
        "risk": "Bolt.new generates complete apps rapidly; common issues include exposed API keys in client-side code, missing auth middleware, and insecure default configurations.",
    },
    "v0.dev (Vercel)": {
        "patterns": [
            r"v0\.dev", r"v0-generated",
            r"generated by v0", r"Built with v0",
            r"v0\.dev/chat",
        ],
        "description": "v0.dev — Vercel's AI UI component generator",
        "risk": "v0 generates UI components that may be integrated without security review. Components may use dangerouslySetInnerHTML or lack input sanitization.",
    },
    "Cursor": {
        "patterns": [
            r"cursor\.sh", r"cursor\.com",
            r"generated.by.cursor", r"cursorapi",
            r"cursor-composer",
        ],
        "description": "Cursor — AI-first code editor with Composer & Agent",
        "risk": "Cursor-generated code may contain AI hallucinated patterns, insecure defaults, or hardcoded development credentials left in production.",
    },
    "Windsurf (Codeium)": {
        "patterns": [
            r"windsurf", r"codeium\.com",
            r"windsurf\.ai", r"codeium",
        ],
        "description": "Windsurf (Codeium) — AI-powered IDE with Cascade agent",
        "risk": "Similar to Cursor — AI-generated code may contain security anti-patterns, especially in auth flows and API integrations.",
    },
    "Create.xyz": {
        "patterns": [
            r"create\.xyz", r"createxyz",
            r"created-with-create", r"\.create\.xyz",
        ],
        "description": "Create.xyz — AI app builder with natural language",
        "risk": "Apps generated via Create.xyz may have minimal security hardening, exposed API routes, and client-side secrets.",
    },
    "Tempo Labs": {
        "patterns": [
            r"tempo\.new", r"tempolabs\.ai",
            r"tempo-generated", r"tempolabs",
        ],
        "description": "Tempo Labs — AI-powered React visual editor",
        "risk": "Tempo-generated React code may include insecure component patterns or exposed configuration data.",
    },
    "Firebase Studio (Project IDX)": {
        "patterns": [
            r"idx\.dev", r"project-idx",
            r"idx\.google\.com", r"firebase\.studio",
        ],
        "description": "Firebase Studio (formerly Project IDX) — Google's AI-powered cloud IDE",
        "risk": "May expose Firebase config, default security rules, or AI-generated backend code with insufficient access control.",
    },
    "Bubble.io": {
        "patterns": [
            r"bubble\.io", r"bubbleapps\.io",
            r"bubble-page", r"\.bubbleio\.",
            r"bdk\.bubble", r"bubble_page_load",
        ],
        "description": "Bubble.io — No-code visual web app builder",
        "risk": "Bubble apps may expose data via poorly configured privacy rules, and API Connector configurations may leak third-party credentials.",
    },
    "Webflow": {
        "patterns": [
            r"webflow\.com", r"webflow\.io",
            r"wf-page", r"w-richtext", r"w-embed",
            r"data-wf-domain", r"data-wf-page",
            r"Webflow", r"webflow-badge",
        ],
        "description": "Webflow — Visual web design and CMS platform",
        "risk": "Webflow sites may expose form submission endpoints, CMS API keys, or custom code embeds with hardcoded secrets.",
    },
    "Framer": {
        "patterns": [
            r"framer\.com", r"framer\.app",
            r"framerusercontent\.com",
            r"data-framer", r"framer-motion",
            r"\.framer\.wiki", r"\.framer\.website",
        ],
        "description": "Framer — Design-to-code website builder",
        "risk": "Framer sites may include custom code overrides with exposed API keys or insecure third-party integrations.",
    },
    "Wix": {
        "patterns": [
            r"wix\.com", r"wixsite\.com",
            r"wix-code", r"wixpress\.com",
            r"X-Wix-", r"static\.parastorage\.com",
            r"_wixCIDX", r"wix-thunderbolt",
        ],
        "description": "Wix — Website builder platform",
        "risk": "Wix sites may have exposed Velo (Wix Code) backend functions, misconfigured data collections, or third-party app API leaks.",
    },
    "Squarespace": {
        "patterns": [
            r"squarespace\.com", r"sqsp\.net",
            r"squarespace-cdn", r"sqs-",
            r"data-squarespace",
        ],
        "description": "Squarespace — Website builder and hosting platform",
        "risk": "Custom code injections in Squarespace may contain hardcoded API keys or insecure form handling.",
    },
    "Softr": {
        "patterns": [
            r"softr\.io", r"softr\.app",
            r"softr-embed", r"\.softr\.",
        ],
        "description": "Softr — No-code app builder (Airtable-powered)",
        "risk": "Softr apps may expose Airtable API keys, base IDs, or misconfigured data access permissions in client-side code.",
    },
    "Glide": {
        "patterns": [
            r"glideapp\.io", r"glide\.page",
            r"glideapps\.com", r"heyglide",
        ],
        "description": "Glide — No-code app builder from spreadsheets",
        "risk": "Glide apps may expose Google Sheets IDs or Airtable connections in client-side requests.",
    },
    "FlutterFlow": {
        "patterns": [
            r"flutterflow\.io", r"flutterflow\.app",
            r"app\.flutterflow", r"ff_theme",
        ],
        "description": "FlutterFlow — Visual app builder for Flutter",
        "risk": "FlutterFlow apps may contain hardcoded Firebase configs, API keys in generated Dart/JS code, and default security rules.",
    },
    "Retool": {
        "patterns": [
            r"retool\.com", r"retool\.dev",
            r"tryretool\.com", r"retoolcdn",
        ],
        "description": "Retool — Low-code internal tools builder",
        "risk": "Retool deployments may expose database connection strings, API configurations, or admin panel access if improperly secured.",
    },
    "Vercel AI SDK": {
        "patterns": [
            r"ai\.vercel\.dev", r"@ai-sdk",
            r"vercel/ai", r"useChat\(",
            r"useCompletion\(", r"streamText\(",
        ],
        "description": "Vercel AI SDK — Framework for building AI-powered apps",
        "risk": "Apps using Vercel AI SDK may expose LLM API keys (OpenAI, Anthropic) in client-side code or have unprotected AI endpoints.",
    },
    "Supabase + AI": {
        "patterns": [
            r"supabase\.co.*?anon.*?key",
            r"NEXT_PUBLIC_SUPABASE", r"VITE_SUPABASE",
            r"createClient\(.*supabase",
        ],
        "description": "Supabase integration (common in vibe-coded apps)",
        "risk": "Exposed Supabase anon keys with permissive RLS policies allow unauthorized data access. Common in Lovable/Bolt/Replit generated apps.",
    },
    "GitHub Copilot": {
        "patterns": [
            r"copilot-generated", r"github\.copilot",
            r"Generated by GitHub Copilot",
        ],
        "description": "GitHub Copilot — AI pair programmer",
        "risk": "Copilot may suggest code with known vulnerabilities, hardcoded example credentials, or insecure patterns from training data.",
    },
    "Devin": {
        "patterns": [
            r"devin\.ai", r"cognition\.ai",
            r"devin-generated",
        ],
        "description": "Devin — Autonomous AI software engineer by Cognition",
        "risk": "Devin-generated code may contain autonomous decisions about security configurations that haven't been human-reviewed.",
    },
    "Netlify Drop / Build": {
        "patterns": [
            r"netlify\.app", r"netlify-cms",
            r"netlify-identity", r"goatcounter.*netlify",
        ],
        "description": "Netlify — Platform often used for deploying vibe-coded projects",
        "risk": "Netlify deployments may expose environment variables via _redirects, netlify.toml, or client-side build artifacts.",
    },
    "Railway": {
        "patterns": [
            r"railway\.app", r"railway\.com",
            r"up\.railway\.app",
        ],
        "description": "Railway — Cloud deployment platform popular with vibe coders",
        "risk": "Railway deployments may expose internal service URLs, database connection strings, or Redis URLs in client-side code.",
    },
    "Render": {
        "patterns": [
            r"onrender\.com", r"render\.com",
        ],
        "description": "Render — Cloud application platform",
        "risk": "Render deployments may expose internal service hostnames or database URLs in frontend code.",
    },
}

