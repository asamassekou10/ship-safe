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
  {
    name: 'Stytch Secret Key',
    pattern: /secret-(?:live|test)-[a-zA-Z0-9]{30,}/g,
    severity: 'critical',
    description: 'Stytch secret keys grant full access to your authentication system.'
  },
  {
    name: 'Okta API Token',
    pattern: /(?:okta|OKTA)[_-]?(?:api[_-]?)?token["']?\s*[:=]\s*["']?(00[a-zA-Z0-9_-]{38})["']?/gi,
    severity: 'high',
    description: 'Okta API tokens can manage your identity provider and user directory.'
  },

  // =========================================================================
  // CRITICAL: Additional Cloud/Infra
  // =========================================================================
  {
    name: 'Azure Storage Connection String',
    pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]{1,50};AccountKey=[a-zA-Z0-9+/=]{44,}/g,
    severity: 'critical',
    description: 'Azure Storage connection strings contain account keys with full storage access.'
  },
  {
    name: 'AWS Session Token',
    pattern: /(?:aws_session_token|aws_security_token)[\s]*[=:][\s]*["']?([A-Za-z0-9/+=]{100,})["']?/gi,
    severity: 'critical',
    description: 'AWS session tokens are temporary credentials that still grant account access.'
  },
  {
    name: 'PlanetScale Service Token',
    pattern: /pscale_tkn_[a-zA-Z0-9_-]{32,}/g,
    severity: 'critical',
    description: 'PlanetScale service tokens grant programmatic database branch access.'
  },
  {
    name: 'Shopify Admin API Access Token',
    pattern: /shpat_[a-fA-F0-9]{32}/g,
    severity: 'critical',
    description: 'Shopify admin tokens grant full store management access including orders and customers.'
  },
  {
    name: 'Shopify Custom App Access Token',
    pattern: /shpca_[a-fA-F0-9]{32}/g,
    severity: 'critical',
    description: 'Shopify custom app tokens provide scoped store admin access.'
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
  // HIGH: AI/ML Providers (2025-2026 additions)
  // =========================================================================
  {
    name: 'xAI (Grok) API Key',
    pattern: /xai-[A-Za-z0-9]{52,}/g,
    severity: 'high',
    description: 'xAI API keys grant access to Grok models and incur usage charges on your account.'
  },
  {
    name: 'Tavily API Key',
    pattern: /tvly-[a-zA-Z0-9]{32,}/g,
    severity: 'high',
    description: 'Tavily API keys grant access to their AI-powered search service.'
  },
  {
    name: 'Cerebras API Key',
    pattern: /csk-[a-zA-Z0-9]{48,}/g,
    severity: 'high',
    description: 'Cerebras API keys provide access to fast AI inference.'
  },
  {
    name: 'Pinecone API Key',
    pattern: /pcsk_[a-zA-Z0-9]{47}_[a-zA-Z0-9]{47}/g,
    severity: 'high',
    description: 'Pinecone API keys grant access to your vector database indexes.'
  },
  {
    name: 'ElevenLabs API Key',
    pattern: /(?:elevenlabs|ELEVENLABS)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-fA-F0-9]{32})["']?/gi,
    severity: 'high',
    description: 'ElevenLabs API keys grant access to their voice AI cloning and synthesis service.'
  },
  {
    name: 'DeepSeek API Key',
    pattern: /(?:deepseek|DEEPSEEK)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?(sk-[a-zA-Z0-9]{32,})["']?/gi,
    severity: 'high',
    description: 'DeepSeek API keys grant access to their language models.'
  },
  {
    name: 'Voyage AI API Key',
    pattern: /(?:voyage|VOYAGE)[_-]?(?:ai[_-]?)?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
    severity: 'high',
    requiresEntropyCheck: true,
    description: 'Voyage AI API keys provide access to their embedding and reranking models.'
  },
  {
    name: 'Fireworks AI API Key',
    pattern: /(?:fireworks|FIREWORKS)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
    severity: 'high',
    requiresEntropyCheck: true,
    description: 'Fireworks AI API keys grant access to fast open-source model inference.'
  },
  {
    name: 'Anyscale API Key',
    pattern: /esecret_[a-zA-Z0-9]{32,}/g,
    severity: 'high',
    description: 'Anyscale API keys grant access to their managed Ray and LLM endpoints.'
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
  {
    name: 'Stripe Restricted Key',
    pattern: /rk_(?:live|test)_[a-zA-Z0-9]{24,}/g,
    severity: 'high',
    description: 'Stripe restricted keys have scoped permissions but still grant API access.'
  },
  {
    name: 'Square Access Token',
    pattern: /EAAAl[0-9a-zA-Z_-]{50,}/g,
    severity: 'high',
    description: 'Square access tokens can process payments and manage store data.'
  },
  {
    name: 'Square OAuth Token',
    pattern: /sq0[a-z]tp-[a-zA-Z0-9_-]{22}/g,
    severity: 'high',
    description: 'Square OAuth tokens authorize Square API access for a merchant account.'
  },
  {
    name: 'Shopify Shared Secret',
    pattern: /shpss_[a-fA-F0-9]{32}/g,
    severity: 'high',
    description: 'Shopify shared secrets validate webhook payload signatures.'
  },
  {
    name: 'Braintree Access Token',
    pattern: /access_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}/g,
    severity: 'critical',
    description: 'Braintree access tokens grant full payment processing access.'
  },

  // =========================================================================
  // HIGH: Realtime & Messaging
  // =========================================================================
  {
    name: 'Pusher App Secret',
    pattern: /(?:pusher|PUSHER)[_-]?(?:app[_-]?)?secret["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: 'high',
    description: 'Pusher app secrets authenticate private and presence channel subscriptions.'
  },
  {
    name: 'Ably API Key',
    pattern: /(?:ably|ABLY)[_-]?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{8}\.[a-zA-Z0-9_-]{6}:[a-zA-Z0-9+/=_-]{43,})["']?/gi,
    severity: 'high',
    description: 'Ably API keys grant full publish and subscribe access to your realtime channels.'
  },
  {
    name: 'Mapbox Access Token',
    pattern: /pk\.eyJ1[a-zA-Z0-9._-]{40,}/g,
    severity: 'medium',
    description: 'Mapbox tokens can incur charges if abused. Restrict token scope and allowed URLs.'
  },

  // =========================================================================
  // HIGH: DevOps & CI/CD
  // =========================================================================
  {
    name: 'CircleCI Personal API Token',
    pattern: /CCIPAT_[a-zA-Z0-9]{40,}/g,
    severity: 'high',
    description: 'CircleCI API tokens can trigger builds, read logs, and access pipeline data.'
  },
  {
    name: 'Sentry Auth Token',
    pattern: /sntrys_[a-zA-Z0-9_]{64,}/g,
    severity: 'high',
    description: 'Sentry auth tokens provide full API access to your error data and project settings.'
  },
  {
    name: 'Terraform Cloud Token',
    pattern: /(?:terraform|TFC)[_-]?(?:api[_-]?)?token["']?\s*[:=]\s*["']?([a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_-]{67,})["']?/gi,
    severity: 'high',
    description: 'Terraform Cloud tokens can read and apply infrastructure state.'
  },
  {
    name: 'Cloudinary API Secret',
    pattern: /(?:cloudinary|CLOUDINARY)[_-]?(?:api[_-]?)?secret["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{27,})["']?/gi,
    severity: 'high',
    requiresEntropyCheck: true,
    description: 'Cloudinary API secrets grant access to your media library and transformations.'
  },
  {
    name: 'Algolia Admin API Key',
    pattern: /(?:algolia|ALGOLIA)[_-]?(?:admin[_-]?)?(?:api[_-]?)?key["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: 'high',
    description: 'Algolia admin keys can modify indices and change search configuration.'
  },
  {
    name: 'LaunchDarkly SDK Key',
    pattern: /sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
    severity: 'high',
    description: 'LaunchDarkly SDK keys can read all feature flags and user data.'
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
  // MEDIUM: Generic patterns (entropy-checked to reduce false positives)
  // requiresEntropyCheck: true → value is scored before reporting
  // =========================================================================
  {
    name: 'Generic API Key Assignment',
    pattern: /["']?(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi,
    severity: 'medium',
    requiresEntropyCheck: true,
    description: 'Hardcoded API keys should be moved to environment variables.'
  },
  {
    name: 'Generic Secret Assignment',
    pattern: /["']?(?:secret|secret[_-]?key)["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi,
    severity: 'medium',
    requiresEntropyCheck: true,
    description: 'Hardcoded secrets should be moved to environment variables.'
  },
  {
    name: 'Password Assignment',
    pattern: /["']?password["']?\s*[:=]\s*["']([^"']{8,})["']/gi,
    severity: 'medium',
    requiresEntropyCheck: true,
    description: 'Hardcoded passwords are a critical vulnerability.'
  },
  {
    name: 'Database URL with Credentials',
    pattern: /(mongodb|postgres|postgresql|mysql|redis):\/\/[^:]+:[^@]+@[^\s"']+/gi,
    severity: 'medium',
    requiresEntropyCheck: true,
    description: 'Database URLs with embedded passwords expose your database.'
  },
  {
    name: 'Bearer Token in Code',
    pattern: /["']Bearer\s+[a-zA-Z0-9_\-\.=]{20,}["']/gi,
    severity: 'medium',
    requiresEntropyCheck: true,
    description: 'Hardcoded bearer tokens should not be in source code.'
  },
  {
    name: 'Basic Auth Header',
    pattern: /["']Basic\s+[A-Za-z0-9+/=]{20,}["']/gi,
    severity: 'medium',
    requiresEntropyCheck: true,
    description: 'Basic auth headers contain base64-encoded credentials.'
  },
  {
    name: 'Private Key in Environment Variable',
    pattern: /PRIVATE[_-]?KEY["']?\s*[:=]\s*["']([^"']+)["']/gi,
    severity: 'high',
    requiresEntropyCheck: true,
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
  '.serverless',
  // Additional build/tooling output
  '.yarn',
  'storybook-static',
  'playwright-report',
  '.playwright',
  '.gradle',
  'target',           // Maven/Gradle build output
  '.pytest_cache',
  '.mypy_cache',
  '.ruff_cache',
  '.tox',
  'site-packages',
  '.pnpm',
  'jspm_packages',
  '.expo',
  '.docusaurus',
  '.storybook',
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

// =============================================================================
// SECURITY VULNERABILITY PATTERNS
// =============================================================================
//
// These patterns detect insecure code patterns (OWASP Top 10, misconfigs, etc.)
// They are distinct from SECRET_PATTERNS:
//   - Secrets    → move to env vars, rotate if exposed
//   - Vulns      → fix the code pattern, can't just rotate
//
// Each pattern includes category: 'vulnerability' to separate output sections.

export const SECURITY_PATTERNS = [

  // =========================================================================
  // XSS — Cross-Site Scripting
  // =========================================================================
  {
    name: 'XSS: dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g,
    severity: 'high',
    category: 'vulnerability',
    description: 'dangerouslySetInnerHTML can introduce XSS if the value contains user input. Sanitize with DOMPurify or restructure to avoid it.'
  },
  {
    name: 'XSS: innerHTML Assignment',
    pattern: /\.innerHTML\s*=/g,
    severity: 'medium',
    category: 'vulnerability',
    description: 'innerHTML set to user-controlled data leads to XSS. Use textContent for plain text or DOMPurify to sanitize HTML.'
  },
  {
    name: 'XSS: document.write',
    pattern: /\bdocument\.write\s*\(/g,
    severity: 'medium',
    category: 'vulnerability',
    description: 'document.write() is deprecated and can introduce XSS. Use DOM manipulation (createElement, appendChild) instead.'
  },

  // =========================================================================
  // Code Injection
  // =========================================================================
  {
    name: 'Code Injection: eval()',
    pattern: /\beval\s*\(/g,
    severity: 'high',
    category: 'vulnerability',
    description: 'eval() executes arbitrary JavaScript and is a serious attack vector. Replace with JSON.parse(), Function calls, or safer alternatives.'
  },
  {
    name: 'Code Injection: new Function()',
    pattern: /\bnew\s+Function\s*\(/g,
    severity: 'high',
    category: 'vulnerability',
    description: 'new Function() is functionally equivalent to eval() and can execute arbitrary code. Avoid dynamic code generation.'
  },

  // =========================================================================
  // SQL Injection
  // =========================================================================
  {
    name: 'SQL Injection: Template Literal Query',
    pattern: /`(?:SELECT|INSERT|UPDATE|DELETE|DROP\s+TABLE|ALTER\s+TABLE)[^`]*\$\{/gi,
    severity: 'critical',
    category: 'vulnerability',
    description: 'SQL queries with interpolated template variables are vulnerable to injection. Use parameterized queries or a query builder.'
  },
  {
    name: 'SQL Injection: String Concatenation Query',
    pattern: /["'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^"']{4,}["']\s*\+/gi,
    severity: 'high',
    category: 'vulnerability',
    description: 'Building SQL with string concatenation is vulnerable to SQL injection. Use parameterized queries (?, $1) or an ORM.'
  },

  // =========================================================================
  // Command Injection
  // =========================================================================
  {
    name: 'Command Injection: exec with Template Literal',
    pattern: /\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{/g,
    severity: 'critical',
    category: 'vulnerability',
    description: 'Running shell commands with interpolated values can lead to command injection. Validate all inputs or use execFile() with argument arrays.'
  },
  {
    name: 'Command Injection: shell: true',
    pattern: /\bspawn(?:Sync)?\s*\([^)]*\bshell\s*:\s*true/g,
    severity: 'high',
    category: 'vulnerability',
    description: 'shell: true in spawn/spawnSync enables shell expansion and can lead to command injection. Remove shell: true and pass arguments as an array.'
  },

  // =========================================================================
  // Weak Cryptography
  // =========================================================================
  {
    name: 'Weak Crypto: MD5',
    pattern: /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
    severity: 'medium',
    category: 'vulnerability',
    description: 'MD5 is cryptographically broken and must not be used for security purposes. Use SHA-256 (createHash("sha256")) or SHA-3.'
  },
  {
    name: 'Weak Crypto: SHA-1',
    pattern: /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
    severity: 'medium',
    category: 'vulnerability',
    description: 'SHA-1 is cryptographically weak and collision-prone. Use SHA-256 (createHash("sha256")) or SHA-3 instead.'
  },

  // =========================================================================
  // TLS / SSL Bypass
  // =========================================================================
  {
    name: 'TLS Bypass: NODE_TLS_REJECT_UNAUTHORIZED=0',
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0['"]?/g,
    severity: 'critical',
    category: 'vulnerability',
    description: 'Setting NODE_TLS_REJECT_UNAUTHORIZED=0 disables TLS certificate validation and exposes your app to MITM attacks. Never use in production.'
  },
  {
    name: 'TLS Bypass: rejectUnauthorized false',
    pattern: /\brejectUnauthorized\s*:\s*false\b/g,
    severity: 'high',
    category: 'vulnerability',
    description: 'rejectUnauthorized: false disables TLS certificate checking and enables man-in-the-middle attacks. Remove it or use a proper CA bundle.'
  },
  {
    name: 'TLS Bypass: verify=False (Python)',
    pattern: /\brequests\.\w+\s*\([^)]*\bverify\s*=\s*False\b/g,
    severity: 'high',
    category: 'vulnerability',
    description: 'verify=False in Python requests disables SSL certificate verification. Remove this or pass verify="/path/to/ca-bundle.crt".'
  },

  // =========================================================================
  // Unsafe Deserialization
  // =========================================================================
  {
    name: 'Unsafe Deserialization: pickle.loads',
    pattern: /\bpickle\.loads?\s*\(/g,
    severity: 'high',
    category: 'vulnerability',
    description: 'pickle.loads() on untrusted data can execute arbitrary Python code (RCE). Use JSON or another safe format for data from untrusted sources.'
  },
  {
    name: 'Unsafe Deserialization: yaml.load',
    pattern: /\byaml\.load\s*\(/g,
    severity: 'medium',
    category: 'vulnerability',
    description: 'yaml.load() can execute arbitrary code with certain YAML tags. Use yaml.safe_load() for untrusted input.'
  },

  // =========================================================================
  // Security Misconfigurations
  // =========================================================================
  {
    name: 'Security Config: CORS Wildcard',
    pattern: /\borigin\s*:\s*['"]?\*['"]?/g,
    severity: 'medium',
    category: 'vulnerability',
    description: 'CORS wildcard (*) allows any origin to make credentialed requests to your API. Use a specific allowlist of trusted origins.'
  },

  // =========================================================================
  // Deprecated / Insecure Node.js APIs
  // =========================================================================
  {
    name: 'Deprecated API: new Buffer()',
    pattern: /\bnew\s+Buffer\s*\(/g,
    severity: 'medium',
    category: 'vulnerability',
    description: 'new Buffer() is deprecated since Node.js 6 and has security implications. Use Buffer.from(), Buffer.alloc(), or Buffer.allocUnsafe().'
  },
];

// =============================================================================
// TEST FILE PATTERNS (skipped by default, override with --include-tests)
// =============================================================================
// Test fixtures are the #1 source of false positives. They contain fake
// credentials, mock data, and example values that look like real secrets.

export const TEST_FILE_PATTERNS = [
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /\.test\.py$/,
  /test_[^/]+\.py$/,
  /__tests__[/\\]/,
  /[/\\]tests?[/\\]/,
  /[/\\]test[/\\]/,
  /[/\\]fixtures?[/\\]/,
  /[/\\]mocks?[/\\]/,
  /[/\\]__mocks__[/\\]/,
  /[/\\]stubs?[/\\]/,
  /[/\\]fakes?[/\\]/,
  /\.stories\.[jt]sx?$/,   // Storybook story files
  /\.mock\.[jt]sx?$/,
];
