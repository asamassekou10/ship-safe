# AI Cost Protection Guide

**Prevent your AI features from bankrupting you.**

Real incidents: $50k+ bills from runaway AI usage, abuse, or misconfiguration.

---

## Why Cost Protection Matters

| Scenario | Risk |
|----------|------|
| Leaked API key | Anyone can rack up charges on your account |
| No rate limits | Single user sends 10,000 requests |
| Long responses | GPT-4 response = $0.03-0.12 per request |
| Infinite loops | Code bug calls AI repeatedly |
| Viral launch | 10x traffic = 10x costs |

---

## Layer 1: API Key Security

### Keep keys server-side only

```typescript
// BAD: Key in frontend code
const openai = new OpenAI({ apiKey: 'sk-...' });

// GOOD: Key in server environment variable
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
```

### Scan for leaked keys

```bash
npx ship-safe scan .
```

### Rotate keys periodically

- OpenAI: Dashboard > API Keys > Create new > Delete old
- Anthropic: Console > API Keys > Rotate

---

## Layer 2: Request Limits

### Token limits per request

```typescript
// Limit input
const MAX_INPUT_CHARS = 2000;
if (userInput.length > MAX_INPUT_CHARS) {
  return "Message too long";
}

// Limit output
const response = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: messages,
  max_tokens: 500,  // Hard cap on response length
});
```

### Rate limiting per user

```typescript
import { Ratelimit } from '@upstash/ratelimit';

const aiRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(10, '1 m'),  // 10 requests/minute
});

async function aiHandler(request, userId) {
  const { success } = await aiRatelimit.limit(userId);
  if (!success) {
    return new Response('Too many requests', { status: 429 });
  }
  // Process request
}
```

### Global rate limiting

```typescript
const globalRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(1000, '1 h'),  // 1000 requests/hour total
  prefix: 'ratelimit:global:ai',
});
```

---

## Layer 3: Budget Caps

### Track usage in database

```typescript
interface AIUsageRecord {
  userId: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  cost: number;
  timestamp: Date;
}

async function logUsage(usage: AIUsageRecord) {
  await db.aiUsage.create({ data: usage });
}
```

### Calculate cost before request

```typescript
// Approximate cost calculation
const COSTS = {
  'gpt-4': { input: 0.03 / 1000, output: 0.06 / 1000 },
  'gpt-4-turbo': { input: 0.01 / 1000, output: 0.03 / 1000 },
  'gpt-3.5-turbo': { input: 0.0005 / 1000, output: 0.0015 / 1000 },
  'claude-3-opus': { input: 0.015 / 1000, output: 0.075 / 1000 },
  'claude-3-sonnet': { input: 0.003 / 1000, output: 0.015 / 1000 },
};

function estimateCost(model: string, inputTokens: number, maxOutputTokens: number) {
  const rates = COSTS[model] || COSTS['gpt-4'];
  return (inputTokens * rates.input) + (maxOutputTokens * rates.output);
}
```

### Enforce user budget

```typescript
async function checkUserBudget(userId: string, estimatedCost: number) {
  const dailyLimit = 1.00;  // $1/day per user
  const monthlyLimit = 10.00;  // $10/month per user

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const dailyUsage = await db.aiUsage.aggregate({
    where: { userId, timestamp: { gte: today } },
    _sum: { cost: true },
  });

  if ((dailyUsage._sum.cost || 0) + estimatedCost > dailyLimit) {
    throw new Error('Daily AI budget exceeded');
  }

  // Similar check for monthly
}
```

### Global budget circuit breaker

```typescript
async function checkGlobalBudget(estimatedCost: number) {
  const monthlyBudget = 500.00;  // $500/month total

  const monthStart = new Date();
  monthStart.setDate(1);
  monthStart.setHours(0, 0, 0, 0);

  const monthlyUsage = await db.aiUsage.aggregate({
    where: { timestamp: { gte: monthStart } },
    _sum: { cost: true },
  });

  if ((monthlyUsage._sum.cost || 0) + estimatedCost > monthlyBudget) {
    // CIRCUIT BREAKER: Disable AI features
    await disableAIFeatures();
    await alertAdmins('AI budget exceeded - features disabled');
    throw new Error('Service temporarily unavailable');
  }
}
```

---

## Layer 4: Provider-Side Limits

### OpenAI usage limits

1. Go to platform.openai.com
2. Settings > Limits
3. Set monthly hard limit

### Anthropic usage limits

1. Go to console.anthropic.com
2. Settings > Usage Limits
3. Set spend limits

### Set up billing alerts

Most providers support alerts at:
- 50% of budget
- 80% of budget
- 100% of budget

---

## Layer 5: Monitoring & Alerts

### Real-time usage dashboard

```typescript
// Track key metrics
const metrics = {
  requestsPerMinute: await getRequestsPerMinute(),
  costToday: await getCostToday(),
  costThisMonth: await getCostThisMonth(),
  topUsers: await getTopUsersByUsage(),
  errorRate: await getErrorRate(),
};
```

### Alert on anomalies

```typescript
async function checkForAnomalies() {
  // Alert if hourly cost exceeds normal
  const hourlyCost = await getHourlyCost();
  const avgHourlyCost = await getAvgHourlyCost();

  if (hourlyCost > avgHourlyCost * 3) {
    await sendAlert({
      type: 'anomaly',
      message: `Hourly AI cost spike: $${hourlyCost} (avg: $${avgHourlyCost})`,
      severity: 'high',
    });
  }

  // Alert if single user is abusing
  const topUser = await getTopUserThisHour();
  if (topUser.requests > 100) {
    await sendAlert({
      type: 'abuse',
      message: `User ${topUser.id} made ${topUser.requests} AI requests this hour`,
      severity: 'medium',
    });
  }
}
```

---

## Cost Comparison: Models

| Model | Input ($/1M tokens) | Output ($/1M tokens) | Best For |
|-------|---------------------|----------------------|----------|
| GPT-4 | $30 | $60 | Complex tasks |
| GPT-4 Turbo | $10 | $30 | Long context |
| GPT-3.5 Turbo | $0.50 | $1.50 | Simple tasks |
| Claude 3 Opus | $15 | $75 | Highest quality |
| Claude 3 Sonnet | $3 | $15 | Balanced |
| Claude 3 Haiku | $0.25 | $1.25 | Speed/cost |

**Tip:** Use cheaper models for simple tasks, reserve expensive models for complex ones.

```typescript
function selectModel(task: string) {
  const simpleTasks = ['summarize', 'classify', 'extract'];
  const complexTasks = ['code', 'analyze', 'create'];

  if (simpleTasks.some(t => task.includes(t))) {
    return 'gpt-3.5-turbo';  // Cheap and fast
  }
  return 'gpt-4-turbo';  // Better but pricier
}
```

---

## Quick Implementation Checklist

1. [ ] API keys in server-side environment variables only
2. [ ] Input length limits (e.g., 2000 chars)
3. [ ] Output token limits (e.g., 500 tokens)
4. [ ] Rate limiting per user (e.g., 10 requests/minute)
5. [ ] Daily budget per user (e.g., $1/day)
6. [ ] Global monthly budget with circuit breaker
7. [ ] Provider-side hard limits configured
8. [ ] Billing alerts at 50%, 80%, 100%
9. [ ] Usage tracking in database
10. [ ] Anomaly detection and alerting

---

**Remember: A $50,000 surprise bill is a real risk. Implement these layers before launch.**
