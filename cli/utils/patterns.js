/**
 * Secret Detection Patterns
 * =========================
 *
 * These regex patterns detect common secret formats.
 * Each pattern includes:
 *   - name: Human-readable identifier
 *   - pattern: Regular expression
 *   - severity: 'critical' | 'high' | 'medium'
 *   - description: Why this matters
 *
 * MAINTENANCE NOTES:
 * - Patterns should have low false-positive rates
 * - Only include patterns with SPECIFIC PREFIXES to avoid noise
 * - Test new patterns against real codebases before adding
 * - Order doesn't matter (all patterns are checked)
 *
 * v1.2.0 - Added 40+ new patterns for 2025-2026 services
 */

export const SECRET_PATTERNS = [
  // =========================================================================
  // CRITICAL: These are almost always real secrets
  // =========================================================================
  {
    name: 'AWS Access Key ID',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    description: 'AWS Access Keys can access your entire AWS account. Rotate immediately if exposed.'
  },
  {
    name: 'AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|aws_secret_key)[\s]*[=:][\s]*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
    description: 'AWS Secret Keys paired with Access Keys grant full AWS access.'
  },
  {
    name: 'GitHub Personal Access Token',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub PATs can access repositories, create commits, and manage settings.'
  },
  {
    name: 'GitHub OAuth Token',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub OAuth tokens grant authorized application access.'
  },
  {
    name: 'GitHub App Token',
    pattern: /ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub App tokens have installation-level access to repositories.'
  },
  {
    name: 'GitHub Fine-Grained PAT',
    pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    severity: 'critical',
    description: 'GitHub fine-grained PATs can access repositories with scoped permissions.'
  },
  {
    name: 'Stripe Live Secret Key',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'critical',
    description: 'Stripe live keys can process real payments and access customer data.'
  },
  {
    name: 'Private Key Block',
    pattern: /-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/g,
    severity: 'critical',
    description: 'Private keys enable impersonation and decryption. Never commit these.'
  },
  {
    name: 'PlanetScale Password',
    pattern: /pscale_pw_[a-zA-Z0-9_-]{32,}/g,
    severity: 'critical',
    description: 'PlanetScale passwords grant database access. Keep in environment variables.'
  },
  {
    name: 'PlanetScale OAuth Token',
    pattern: /pscale_oauth_[a-zA-Z0-9_-]{32,}/g,
    severity: 'critical',
    description: 'PlanetScale OAuth tokens can manage your database branches and schema.'
  },
  {
    name: 'Clerk Secret Key',
    pattern: /sk_live_[a-zA-Z0-9]{27,}/g,
    severity: 'critical',
    description: 'Clerk secret keys grant full access to your auth system. Never expose in frontend.'
  },
  {
    name: 'Doppler Service Token',
    pattern: /dp\.st\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9]{32,}/g,
    severity: 'critical',
    description: 'Doppler service tokens grant access to your secrets. Ironic if leaked!'
  },
  {
    name: 'HashiCorp Vault Token',
    pattern: /hvs\.[a-zA-Z0-9_-]{24,}/g,
    severity: 'critical',
    description: 'HashiCorp Vault tokens grant access to your secrets.'
  },
  {
    name: 'Neon Database Connection String',
    pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^.]+\.neon\.tech/g,
    severity: 'critical',
    description: 'Neon Postgres connection strings contain database credentials.'
  },
  {
    name: 'MongoDB Atlas Connection String',
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^.]+\.mongodb\.net/g,
    severity: 'critical',
    description: 'MongoDB Atlas connection strings contain database credentials.'
  },

  // =========================================================================
  // HIGH: AI/ML Provider Keys (2025-2026)
  // =========================================================================
  {
    name: 'OpenAI API Key',
    pattern: /sk-[a-zA-Z0-9]{20,}/g,
    severity: 'high',
    description: 'OpenAI keys can rack up API charges and access your usage history.'
  },
  {
    name: 'OpenAI Project Key',
    pattern: /sk-proj-[a-zA-Z0-9_-]{48,}/g,
    severity: 'high',
    description: 'OpenAI project keys grant access to specific project resources.'
  },
  {
    name: 'Anthropic API Key',
    pattern: /sk-ant-[a-zA-Z0-9_-]{32,}/g,
    severity: 'high',
    description: 'Anthropic API keys grant access to Claude and your usage quota.'
  },
  {
    name: 'Google AI (Gemini) API Key',
    pattern: /AIzaSy[a-zA-Z0-9_-]{33}/g,
    severity: 'high',
    description: 'Google AI API keys grant access to Gemini and other Google AI services.'
  },
  {
    name: 'Replicate API Token',
    pattern: /r8_[a-zA-Z0-9]{37}/g,
    severity: 'high',
    description: 'Replicate tokens can run AI models and incur charges on your account.'
  },
  {
    name: 'Hugging Face Token',
    pattern: /hf_[a-zA-Z0-9]{34}/g,
    severity: 'high',
    description: 'Hugging Face tokens grant access to models, datasets, and Inference API.'
  },
  {
    name: 'Perplexity API Key',
    pattern: /pplx-[a-f0-9]{48}/g,
    severity: 'high',
    description: 'Perplexity API keys can access their search-augmented AI models.'
  },
  {
    name: 'Groq API Key',
    pattern: /gsk_[a-zA-Z0-9]{52}/g,
    severity: 'high',
    description: 'Groq API keys provide access to fast LLM inference.'
  },
  {
    name: 'Cohere API Key',
    pattern: /(?:cohere|COHERE)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-zA-Z0-9]{40})["']?/gi,
    severity: 'high',
    description: 'Cohere API keys grant access to their NLP models.'
  },
  {
    name: 'Mistral API Key',
    pattern: /(?:mistral|MISTRAL)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
    severity: 'high',
    description: 'Mistral AI API keys can access their language models.'
  },
  {
    name: 'Together AI API Key',
    pattern: /(?:together|TOGETHER)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-f0-9]{64})["']?/gi,
    severity: 'high',
    description: 'Together AI keys grant access to open-source model hosting.'
  },

  // =========================================================================
  // HIGH: Communication & Messaging
  // =========================================================================
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g,
    severity: 'high',
    description: 'Slack tokens can read messages, post content, and access workspace data.'
  },
  {
    name: 'Slack Webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    severity: 'high',
    description: 'Slack webhooks allow posting messages to channels.'
  },
  {
    name: 'Discord Webhook',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+/g,
    severity: 'high',
    description: 'Discord webhooks allow posting messages to channels.'
  },
  {
    name: 'Discord Bot Token',
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    severity: 'high',
    description: 'Discord bot tokens grant full control over your bot.'
  },
  {
    name: 'Telegram Bot Token',
    pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
    severity: 'high',
    description: 'Telegram bot tokens grant full control over your bot.'
  },

  // =========================================================================
  // HIGH: Email Services
  // =========================================================================
  {
    name: 'SendGrid API Key',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'high',
    description: 'SendGrid keys can send emails from your account.'
  },
  {
    name: 'Mailgun API Key',
    pattern: /key-[a-zA-Z0-9]{32}/g,
    severity: 'high',
    description: 'Mailgun keys can send emails and access logs.'
  },
  {
    name: 'Resend API Key',
    pattern: /re_[a-zA-Z0-9]{32,}/g,
    severity: 'high',
    description: 'Resend API keys can send emails from your account and access logs.'
  },
  {
    name: 'Postmark Server Token',
    pattern: /(?:postmark|POSTMARK)[_-]?(?:server[_-]?)?token["']?\s*[:=]\s*["']?([a-f0-9-]{36})["']?/gi,
    severity: 'high',
    description: 'Postmark tokens can send emails from your account.'
  },
  {
    name: 'Mailchimp API Key',
    pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g,
    severity: 'high',
    description: 'Mailchimp API keys can access your audience and send campaigns.'
  },

  // =========================================================================
  // HIGH: SMS & Phone
  // =========================================================================
  {
    name: 'Twilio API Key',
    pattern: /SK[a-f0-9]{32}/g,
    severity: 'high',
    description: 'Twilio keys can send SMS/calls and access account data.'
  },
  {
    name: 'Twilio Account SID',
    pattern: /AC[a-f0-9]{32}/g,
    severity: 'medium',
    description: 'Twilio Account SIDs identify your account. Usually paired with auth token.'
  },

  // =========================================================================
  // HIGH: Databases & Backend Services
  // =========================================================================
  {
    name: 'Firebase/Google Service Account',
    pattern: /"type":\s*"service_account"/g,
    severity: 'high',
    description: 'Service account JSON files grant broad GCP/Firebase access.'
  },
  {
    name: 'Supabase Service Role Key',
    pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    severity: 'high',
    description: 'Supabase service role keys bypass Row Level Security. Keep server-side only.'
  },
  {
    name: 'Upstash Redis REST Token',
    pattern: /AX[a-zA-Z0-9]{34,}/g,
    severity: 'high',
    description: 'Upstash Redis tokens grant access to your serverless Redis database.'
  },
  {
    name: 'Upstash QStash Token',
    pattern: /qstash_[a-zA-Z0-9]{32,}/g,
    severity: 'high',
    description: 'Upstash QStash tokens can schedule and manage message queues.'
  },
  {
    name: 'Turso Database URL',
    pattern: /libsql:\/\/[^.]+\.turso\.io/g,
    severity: 'high',
    description: 'Turso database URLs. Check for embedded auth tokens in full connection string.'
  },
  {
    name: 'Convex Deployment URL',
    pattern: /https:\/\/[a-z]+-[a-z]+-[0-9]+\.convex\.cloud/g,
    severity: 'medium',
    description: 'Convex deployment URLs identify your backend. Check for paired secrets.'
  },

  // =========================================================================
  // HIGH: Hosting & Deployment
  // =========================================================================
  {
    name: 'Vercel Token',
    pattern: /vercel_[a-zA-Z0-9]{24}/gi,
    severity: 'high',
    description: 'Vercel tokens can deploy and manage your projects.'
  },
  {
    name: 'NPM Token',
    pattern: /npm_[a-zA-Z0-9]{36}/g,
    severity: 'high',
    description: 'NPM tokens can publish packages under your account.'
  },
  {
    name: 'Heroku API Key',
    pattern: /[hH]eroku.*[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
    severity: 'high',
    description: 'Heroku API keys can manage apps and dynos.'
  },
  {
    name: 'DigitalOcean Token',
    pattern: /dop_v1_[a-f0-9]{64}/g,
    severity: 'high',
    description: 'DigitalOcean tokens can manage droplets and resources.'
  },
  {
    name: 'Render API Key',
    pattern: /rnd_[a-zA-Z0-9]{32,}/g,
    severity: 'high',
    description: 'Render API keys can manage your services and deployments.'
  },
  {
    name: 'Fly.io Token',
    pattern: /FlyV1\s+[a-zA-Z0-9_-]{43}/g,
    severity: 'high',
    description: 'Fly.io tokens can deploy and manage your applications.'
  },
  {
    name: 'Railway Token',
    pattern: /(?:railway|RAILWAY)[_-]?token["']?\s*[:=]\s*["']?([a-f0-9-]{36})["']?/gi,
    severity: 'high',
    description: 'Railway API tokens can manage your services.'
  },
  {
    name: 'Netlify Personal Access Token',
    pattern: /nfp_[a-zA-Z0-9]{40}/g,
    severity: 'high',
    description: 'Netlify PATs can manage sites and deploys.'
  },
  {
    name: 'Cloudflare API Token',
    pattern: /(?:cloudflare|CF)[_-]?(?:api[_-]?)?token["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{40})["']?/gi,
    severity: 'high',
    description: 'Cloudflare API tokens can manage DNS, workers, and other services.'
  },

  // =========================================================================
  // HIGH: Auth Providers
  // =========================================================================
  {
    name: 'Clerk Publishable Key (Live)',
    pattern: /pk_live_[a-zA-Z0-9]{27,}/g,
    severity: 'medium',
    description: 'Clerk publishable keys are meant for frontend but verify it\'s intentional.'
  },
  {
    name: 'Clerk Test Secret Key',
    pattern: /sk_test_[a-zA-Z0-9]{27,}/g,
    severity: 'medium',
    description: 'Clerk test keys are lower risk but should still be in environment variables.'
  },
  {
    name: 'Auth0 Domain with Credentials',
    pattern: /https:\/\/[^.]+\.auth0\.com.*client_secret/gi,
    severity: 'critical',
    description: 'Auth0 URLs with embedded client secrets should never be in code.'
  },
  {
    name: 'Supabase Anon Key in Code',
    pattern: /(?:supabase|SUPABASE)[_-]?(?:anon[_-]?)?key["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']?/gi,
    severity: 'medium',
    description: 'Supabase anon keys. Safe for frontend but verify RLS is enabled.'
  },

  // =========================================================================
  // HIGH: Productivity & SaaS
  // =========================================================================
  {
    name: 'Linear API Key',
    pattern: /lin_api_[a-zA-Z0-9]{40}/g,
    severity: 'high',
    description: 'Linear API keys can access your project management data.'
  },
  {
    name: 'Notion API Key',
    pattern: /secret_[a-zA-Z0-9]{43}/g,
    severity: 'high',
    description: 'Notion API keys can access and modify your workspace content.'
  },
  {
    name: 'Airtable API Key',
    pattern: /pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}/g,
    severity: 'high',
    description: 'Airtable personal access tokens grant access to your bases.'
  },
  {
    name: 'Figma Personal Access Token',
    pattern: /figd_[a-zA-Z0-9_-]{40,}/g,
    severity: 'high',
    description: 'Figma PATs can access your design files and projects.'
  },

  // =========================================================================
  // HIGH: Payments (Additional)
  // =========================================================================
  {
    name: 'Stripe Test Secret Key',
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    severity: 'medium',
    description: 'Stripe test keys are lower risk but should still be in environment variables.'
  },
  {
    name: 'Stripe Live Publishable Key',
    pattern: /pk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'medium',
    description: 'Stripe publishable keys are meant for frontend but verify it\'s intentional.'
  },
  {
    name: 'Stripe Webhook Secret',
    pattern: /whsec_[a-zA-Z0-9]{32,}/g,
    severity: 'high',
    description: 'Stripe webhook secrets validate incoming webhooks. Keep server-side only.'
  },
  {
    name: 'Lemon Squeezy API Key',
    pattern: /(?:lemon|LEMON)[_-]?(?:squeezy|SQUEEZY)?[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-f0-9-]{36})["']?/gi,
    severity: 'high',
    description: 'Lemon Squeezy API keys can manage your store and orders.'
  },
  {
    name: 'Paddle API Key',
    pattern: /(?:paddle|PADDLE)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-f0-9]{64})["']?/gi,
    severity: 'high',
    description: 'Paddle API keys can manage your subscriptions and payments.'
  },

  // =========================================================================
  // HIGH: Analytics & Monitoring
  // =========================================================================
  {
    name: 'Sentry DSN',
    pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/g,
    severity: 'medium',
    description: 'Sentry DSNs are semi-public but contain project identifiers.'
  },
  {
    name: 'PostHog API Key',
    pattern: /phc_[a-zA-Z0-9]{32,}/g,
    severity: 'medium',
    description: 'PostHog project API keys. Usually safe in frontend but verify.'
  },
  {
    name: 'New Relic API Key',
    pattern: /NRAK-[A-Z0-9]{27}/g,
    severity: 'high',
    description: 'New Relic API keys can access your monitoring data and configurations.'
  },
  {
    name: 'Datadog API Key',
    pattern: /(?:datadog|DD)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: 'high',
    description: 'Datadog API keys can access and send monitoring data.'
  },

  // =========================================================================
  // MEDIUM: Generic patterns (may have false positives)
  // =========================================================================
  {
    name: 'Generic API Key Assignment',
    pattern: /["']?(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi,
    severity: 'medium',
    description: 'Hardcoded API keys should be moved to environment variables.'
  },
  {
    name: 'Generic Secret Assignment',
    pattern: /["']?(?:secret|secret[_-]?key)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi,
    severity: 'medium',
    description: 'Hardcoded secrets should be moved to environment variables.'
  },
  {
    name: 'Password Assignment',
    pattern: /["']?password["']?\s*[:=]\s*["']([^"']{8,})["']/gi,
    severity: 'medium',
    description: 'Hardcoded passwords are a critical vulnerability.'
  },
  {
    name: 'Database URL with Credentials',
    pattern: /(mongodb|postgres|postgresql|mysql|redis):\/\/[^:]+:[^@]+@[^\s"']+/gi,
    severity: 'medium',
    description: 'Database URLs with embedded passwords expose your database.'
  },
  {
    name: 'Bearer Token in Code',
    pattern: /["']Bearer\s+[a-zA-Z0-9_\-\.=]{20,}["']/gi,
    severity: 'medium',
    description: 'Hardcoded bearer tokens should not be in source code.'
  },
  {
    name: 'Basic Auth Header',
    pattern: /["']Basic\s+[A-Za-z0-9+/=]{20,}["']/gi,
    severity: 'medium',
    description: 'Basic auth headers contain base64-encoded credentials.'
  },
  {
    name: 'Private Key in Environment Variable',
    pattern: /PRIVATE[_-]?KEY["']?\s*[:=]\s*["']([^"']+)["']/gi,
    severity: 'high',
    description: 'Private keys should be loaded from files, not hardcoded.'
  }
];

// =============================================================================
// FILES AND DIRECTORIES TO SKIP
// =============================================================================

export const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'venv',
  'env',
  '.venv',
  '__pycache__',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  '.output',
  'coverage',
  '.nyc_output',
  'vendor',
  '.bundle',
  '.cache',
  '.parcel-cache',
  '.turbo',
  'bower_components',
  'jspm_packages',
  '.vercel',
  '.netlify',
  '.serverless'
]);

export const SKIP_EXTENSIONS = new Set([
  // Images
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff',
  // Fonts
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  // Media
  '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm', '.ogg',
  // Archives
  '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
  // Documents
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  // Lock files (usually very large and auto-generated)
  '.lock',
  // Minified files
  '.min.js', '.min.css',
  // Binaries
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
  // Maps
  '.map'
]);

// Maximum file size to scan (1MB)
export const MAX_FILE_SIZE = 1_000_000;
