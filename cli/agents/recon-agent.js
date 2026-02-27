/**
 * ReconAgent — Attack Surface Discovery
 * =======================================
 *
 * Maps the full attack surface before other agents run.
 * Detects frameworks, API routes, auth patterns, databases,
 * cloud providers, and frontend exposure.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent } from './base-agent.js';

export class ReconAgent extends BaseAgent {
  constructor() {
    super('ReconAgent', 'Attack surface discovery and mapping', 'recon');
  }

  async analyze(context) {
    const { rootPath } = context;
    const files = await this.discoverFiles(rootPath);

    const recon = {
      frameworks: [],
      languages: new Set(),
      apiRoutes: [],
      authPatterns: [],
      databases: [],
      cloudProviders: [],
      frontendExposure: [],
      packageManagers: [],
      cicd: [],
      hasDockerfile: false,
      hasTerraform: false,
      hasKubernetes: false,
      envFiles: [],
      configFiles: [],
    };

    // ── Detect by config files ────────────────────────────────────────────────
    for (const file of files) {
      const basename = path.basename(file);
      const relPath = path.relative(rootPath, file).replace(/\\/g, '/');
      const ext = path.extname(file).toLowerCase();

      // Languages
      if (['.js', '.jsx', '.mjs', '.cjs'].includes(ext)) recon.languages.add('javascript');
      if (['.ts', '.tsx'].includes(ext)) recon.languages.add('typescript');
      if (ext === '.py') recon.languages.add('python');
      if (ext === '.rb') recon.languages.add('ruby');
      if (ext === '.go') recon.languages.add('go');
      if (ext === '.java') recon.languages.add('java');
      if (ext === '.rs') recon.languages.add('rust');
      if (ext === '.php') recon.languages.add('php');

      // Frameworks
      if (basename === 'next.config.js' || basename === 'next.config.mjs' || basename === 'next.config.ts') {
        recon.frameworks.push('nextjs');
      }
      if (basename === 'nuxt.config.ts' || basename === 'nuxt.config.js') recon.frameworks.push('nuxtjs');
      if (basename === 'svelte.config.js') recon.frameworks.push('sveltekit');
      if (basename === 'remix.config.js') recon.frameworks.push('remix');
      if (basename === 'astro.config.mjs' || basename === 'astro.config.ts') recon.frameworks.push('astro');
      if (basename === 'angular.json') recon.frameworks.push('angular');
      if (basename === 'vite.config.ts' || basename === 'vite.config.js') recon.frameworks.push('vite');
      if (basename === 'manage.py') recon.frameworks.push('django');
      if (basename === 'Gemfile' && this.readFile(file)?.includes('rails')) recon.frameworks.push('rails');
      if (basename === 'pubspec.yaml') recon.frameworks.push('flutter');

      // API Routes
      if (relPath.match(/app\/api\/.*\.(js|ts)$/) || relPath.match(/pages\/api\/.*\.(js|ts)$/)) {
        recon.apiRoutes.push(relPath);
      }
      if (relPath.match(/routes?\.(js|ts)$/) || relPath.match(/router\.(js|ts)$/)) {
        recon.apiRoutes.push(relPath);
      }
      if (relPath.match(/urls\.py$/)) recon.apiRoutes.push(relPath);
      if (relPath.match(/controllers?\/.*\.(js|ts|rb)$/)) recon.apiRoutes.push(relPath);

      // Auth
      if (basename === 'auth.ts' || basename === 'auth.js' || relPath.includes('auth/')) {
        recon.authPatterns.push(relPath);
      }
      if (basename === 'middleware.ts' || basename === 'middleware.js') {
        recon.authPatterns.push(relPath);
      }

      // Databases
      if (basename === 'schema.prisma') recon.databases.push('prisma');
      if (basename === 'drizzle.config.ts' || basename === 'drizzle.config.js') recon.databases.push('drizzle');
      if (relPath.includes('models/') && ['.py', '.rb'].includes(ext)) recon.databases.push('orm');

      // Cloud
      if (basename === 'vercel.json') recon.cloudProviders.push('vercel');
      if (basename === 'netlify.toml') recon.cloudProviders.push('netlify');
      if (basename === 'fly.toml') recon.cloudProviders.push('fly');
      if (basename === 'app.yaml' || basename === 'app.yml') recon.cloudProviders.push('gcp');
      if (basename === 'serverless.yml' || basename === 'serverless.yaml') recon.cloudProviders.push('aws-serverless');
      if (basename === 'render.yaml') recon.cloudProviders.push('render');
      if (basename === 'railway.json') recon.cloudProviders.push('railway');

      // IaC
      if (ext === '.tf') recon.hasTerraform = true;
      if (basename === 'Dockerfile' || basename.startsWith('Dockerfile.')) recon.hasDockerfile = true;
      if (basename.match(/\.ya?ml$/) && relPath.match(/(k8s|kubernetes|deploy|helm)/i)) {
        recon.hasKubernetes = true;
      }

      // CI/CD
      if (relPath.startsWith('.github/workflows/')) recon.cicd.push({ platform: 'github-actions', file: relPath });
      if (basename === '.gitlab-ci.yml') recon.cicd.push({ platform: 'gitlab', file: relPath });
      if (basename === 'Jenkinsfile') recon.cicd.push({ platform: 'jenkins', file: relPath });
      if (basename === '.circleci/config.yml' || relPath.startsWith('.circleci/')) recon.cicd.push({ platform: 'circleci', file: relPath });
      if (basename === 'bitbucket-pipelines.yml') recon.cicd.push({ platform: 'bitbucket', file: relPath });
      if (basename === 'azure-pipelines.yml') recon.cicd.push({ platform: 'azure', file: relPath });

      // Package managers
      if (basename === 'package.json') recon.packageManagers.push('npm');
      if (basename === 'Pipfile' || basename === 'requirements.txt' || basename === 'pyproject.toml') recon.packageManagers.push('pip');
      if (basename === 'Gemfile') recon.packageManagers.push('bundler');
      if (basename === 'go.mod') recon.packageManagers.push('go');
      if (basename === 'Cargo.toml') recon.packageManagers.push('cargo');
      if (basename === 'composer.json') recon.packageManagers.push('composer');

      // Env files
      if (basename.startsWith('.env')) recon.envFiles.push(relPath);

      // Config files
      if (['vercel.json', 'netlify.toml', 'next.config.js', 'next.config.mjs',
           'next.config.ts', 'docker-compose.yml', 'docker-compose.yaml',
           'nginx.conf', 'Caddyfile', 'firebase.json', 'supabase/config.toml'
          ].includes(basename)) {
        recon.configFiles.push(relPath);
      }
    }

    // ── Detect frontend exposure from package.json ────────────────────────────
    const pkgPath = path.join(rootPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

        if (allDeps['express']) recon.frameworks.push('express');
        if (allDeps['fastify']) recon.frameworks.push('fastify');
        if (allDeps['hono']) recon.frameworks.push('hono');
        if (allDeps['@hono/node-server']) recon.frameworks.push('hono');
        if (allDeps['koa']) recon.frameworks.push('koa');
        if (allDeps['flask'] || allDeps['Flask']) recon.frameworks.push('flask');
        if (allDeps['fastapi'] || allDeps['FastAPI']) recon.frameworks.push('fastapi');

        // Auth libraries
        if (allDeps['next-auth'] || allDeps['@auth/core']) recon.authPatterns.push('next-auth');
        if (allDeps['@clerk/nextjs'] || allDeps['@clerk/clerk-react']) recon.authPatterns.push('clerk');
        if (allDeps['@supabase/supabase-js']) { recon.authPatterns.push('supabase-auth'); recon.databases.push('supabase'); }
        if (allDeps['firebase']) { recon.authPatterns.push('firebase-auth'); recon.databases.push('firebase'); }
        if (allDeps['jsonwebtoken'] || allDeps['jose']) recon.authPatterns.push('jwt');
        if (allDeps['passport']) recon.authPatterns.push('passport');

        // Databases
        if (allDeps['@prisma/client'] || allDeps['prisma']) recon.databases.push('prisma');
        if (allDeps['drizzle-orm']) recon.databases.push('drizzle');
        if (allDeps['sequelize']) recon.databases.push('sequelize');
        if (allDeps['typeorm']) recon.databases.push('typeorm');
        if (allDeps['mongoose'] || allDeps['mongodb']) recon.databases.push('mongodb');
        if (allDeps['pg'] || allDeps['postgres']) recon.databases.push('postgres');
        if (allDeps['mysql2'] || allDeps['mysql']) recon.databases.push('mysql');
        if (allDeps['@upstash/redis']) recon.databases.push('upstash-redis');

        // AI/LLM
        if (allDeps['openai'] || allDeps['@anthropic-ai/sdk'] || allDeps['ai']) {
          recon.frameworks.push('ai-app');
        }

        // Mobile
        if (allDeps['react-native'] || allDeps['expo']) recon.frameworks.push('react-native');

      } catch { /* skip parse errors */ }
    }

    // Deduplicate arrays
    recon.frameworks = [...new Set(recon.frameworks)];
    recon.languages = [...recon.languages];
    recon.authPatterns = [...new Set(recon.authPatterns)];
    recon.databases = [...new Set(recon.databases)];
    recon.cloudProviders = [...new Set(recon.cloudProviders)];
    recon.packageManagers = [...new Set(recon.packageManagers)];

    // Store on context for other agents
    if (context) context.recon = recon;

    return recon;
  }
}

export default ReconAgent;
