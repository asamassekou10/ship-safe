/**
 * MobileScanner Agent
 * ====================
 *
 * Security scanning for React Native, Expo, Flutter,
 * and native mobile codebases.
 * Based on OWASP Mobile Top 10 2024.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

const PATTERNS = [
  // ── M1: Improper Credential Usage ──────────────────────────────────────────
  {
    rule: 'MOBILE_HARDCODED_KEY',
    title: 'Mobile: Hardcoded API Key in Bundle',
    regex: /(?:apiKey|api_key|API_KEY|secret|SECRET)\s*[:=]\s*["'][a-zA-Z0-9_\-]{20,}["']/g,
    severity: 'critical',
    cwe: 'CWE-798',
    owasp: 'M1',
    description: 'Hardcoded API key in mobile code. Mobile bundles are easily decompiled.',
    fix: 'Store secrets server-side. Use expo-secure-store or EncryptedSharedPreferences.',
  },
  {
    rule: 'MOBILE_KEY_IN_CONFIG',
    title: 'Mobile: Secret in app.json/app.config.js',
    regex: /(?:apiKey|apiSecret|secret|token|password|private_key)\s*["']?\s*[:=]\s*["'][^"']{8,}["']/gi,
    severity: 'high',
    cwe: 'CWE-798',
    owasp: 'M1',
    description: 'Secret in app config file. This gets bundled into the app binary.',
    fix: 'Move to environment variables or server-side configuration',
  },

  // ── M3: Insecure Authentication/Authorization ──────────────────────────────
  {
    rule: 'MOBILE_LOCAL_AUTH_ONLY',
    title: 'Mobile: Client-Only Authentication',
    regex: /(?:isAuthenticated|isLoggedIn|isAdmin)\s*[:=]\s*(?:AsyncStorage|localStorage|SecureStore)/g,
    severity: 'high',
    cwe: 'CWE-603',
    owasp: 'M3',
    description: 'Authentication state stored only on client. Attacker can bypass by modifying storage.',
    fix: 'Verify authentication server-side on every API request',
  },

  // ── M4: Insufficient Input/Output Validation ──────────────────────────────
  {
    rule: 'MOBILE_WEBVIEW_JS',
    title: 'Mobile: WebView JavaScript Enabled',
    regex: /(?:javaScriptEnabled|javascriptEnabled)\s*[:=]\s*(?:\{?\s*true|True)/g,
    severity: 'medium',
    cwe: 'CWE-79',
    owasp: 'M4',
    description: 'WebView with JavaScript enabled can be exploited via injected content.',
    fix: 'Disable JavaScript in WebViews loading untrusted content, or sanitize loaded HTML',
  },
  {
    rule: 'MOBILE_DEEPLINK_INJECTION',
    title: 'Mobile: Deep Link Parameter Injection',
    regex: /(?:Linking\.getInitialURL|useURL|addEventListener\s*\(\s*['"]url['"])/g,
    severity: 'high',
    cwe: 'CWE-20',
    owasp: 'M4',
    confidence: 'low',
    description: 'Deep link URL handler detected. Ensure parameters from deep links are validated before use.',
    fix: 'Validate and sanitize all parameters from deep links before use',
  },

  // ── M5: Insecure Communication ─────────────────────────────────────────────
  {
    rule: 'MOBILE_HTTP_ENDPOINT',
    title: 'Mobile: HTTP (Non-HTTPS) Endpoint',
    regex: /(?:baseURL|apiUrl|endpoint|url|API_URL)\s*[:=]\s*["']http:\/\//gi,
    severity: 'high',
    cwe: 'CWE-319',
    owasp: 'M5',
    description: 'HTTP endpoint in mobile app. All traffic is unencrypted and interceptable.',
    fix: 'Use HTTPS for all endpoints. Configure ATS (iOS) and cleartextTraffic (Android).',
  },
  {
    rule: 'MOBILE_NO_CERT_PINNING',
    title: 'Mobile: Missing Certificate Pinning',
    regex: /(?:fetch|axios|http)\s*\(\s*(?!.*pin|certificate)/g,
    severity: 'medium',
    cwe: 'CWE-295',
    owasp: 'M5',
    confidence: 'low',
    description: 'No certificate pinning detected. MITM attacks possible on compromised networks.',
    fix: 'Implement cert pinning with react-native-ssl-pinning or TrustKit',
  },

  // ── M6: Inadequate Privacy Controls ────────────────────────────────────────
  {
    rule: 'MOBILE_EXCESSIVE_PERMISSIONS',
    title: 'Mobile: Excessive Permissions',
    regex: /(?:CAMERA|CONTACTS|LOCATION|MICROPHONE|CALENDAR|READ_SMS|CALL_LOG|READ_PHONE_STATE)\s*(?:[,\]])/g,
    severity: 'medium',
    cwe: 'CWE-250',
    owasp: 'M6',
    confidence: 'low',
    description: 'Multiple sensitive permissions requested. Only request what is needed.',
    fix: 'Remove unnecessary permissions. Request at runtime with clear justification.',
  },

  // ── M8: Security Misconfiguration ──────────────────────────────────────────
  {
    rule: 'MOBILE_DEBUG_BUILD',
    title: 'Mobile: Debug Mode in Release',
    regex: /(?:__DEV__|debuggable\s*[:=]\s*true|android:debuggable="true"|DEBUG_MODE\s*[:=]\s*true)/g,
    severity: 'high',
    cwe: 'CWE-215',
    owasp: 'M8',
    description: 'Debug mode enabled. Exposes debugging interfaces and detailed error messages.',
    fix: 'Ensure __DEV__ checks are used correctly. Set debuggable=false in release builds.',
  },
  {
    rule: 'MOBILE_BACKUP_ENABLED',
    title: 'Mobile: App Backup Enabled',
    regex: /(?:android:allowBackup="true"|allowsBackup\s*[:=]\s*true)/g,
    severity: 'medium',
    cwe: 'CWE-312',
    owasp: 'M8',
    description: 'App backup enabled. Sensitive data can be extracted from backups.',
    fix: 'Set android:allowBackup="false" and exclude sensitive files from backup',
  },

  // ── M9: Insecure Data Storage ──────────────────────────────────────────────
  {
    rule: 'MOBILE_ASYNCSTORAGE_SECRET',
    title: 'Mobile: Secret in AsyncStorage',
    regex: /AsyncStorage\.setItem\s*\(\s*["'](?:.*(?:token|key|secret|password|credential|session))/gi,
    severity: 'high',
    cwe: 'CWE-312',
    owasp: 'M9',
    description: 'Storing secrets in AsyncStorage (unencrypted). Use expo-secure-store or Keychain.',
    fix: 'Use expo-secure-store (Expo) or react-native-keychain for sensitive data',
  },
  {
    rule: 'MOBILE_LOCALSTORAGE_SECRET',
    title: 'Mobile: Secret in localStorage',
    regex: /localStorage\.setItem\s*\(\s*["'](?:.*(?:token|key|secret|password|credential|session))/gi,
    severity: 'high',
    cwe: 'CWE-312',
    owasp: 'M9',
    description: 'Storing secrets in localStorage (unencrypted). Use secure storage APIs.',
    fix: 'Use platform-specific secure storage: Keychain (iOS), EncryptedSharedPreferences (Android)',
  },
  {
    rule: 'MOBILE_LOG_SENSITIVE',
    title: 'Mobile: Sensitive Data in Logs',
    regex: /console\.(?:log|info|warn|debug)\s*\(\s*.*(?:token|password|secret|key|credential|session|auth)/gi,
    severity: 'medium',
    cwe: 'CWE-532',
    owasp: 'M9',
    confidence: 'medium',
    description: 'Sensitive data logged to console. Logs are accessible on rooted/jailbroken devices.',
    fix: 'Remove sensitive data from console.log. Use __DEV__ check for debug logging.',
  },

  // ── M10: Insufficient Cryptography ─────────────────────────────────────────
  {
    rule: 'MOBILE_HARDCODED_CRYPTO_KEY',
    title: 'Mobile: Hardcoded Encryption Key',
    regex: /(?:encrypt|cipher|aes|crypto).*(?:key|iv|salt)\s*[:=]\s*["'][a-zA-Z0-9+/=]{8,}["']/gi,
    severity: 'critical',
    cwe: 'CWE-321',
    owasp: 'M10',
    description: 'Hardcoded encryption key in mobile code. Easily extracted from decompiled binary.',
    fix: 'Derive keys from user credentials or fetch from server at runtime',
  },

  // ── Flutter-specific ───────────────────────────────────────────────────────
  {
    rule: 'FLUTTER_SHARED_PREFS_SECRET',
    title: 'Flutter: Secret in SharedPreferences',
    regex: /SharedPreferences.*(?:setString|setInt)\s*\(\s*["'](?:.*(?:token|key|secret|password|api))/gi,
    severity: 'high',
    cwe: 'CWE-312',
    owasp: 'M9',
    description: 'Storing secrets in SharedPreferences (unencrypted). Use flutter_secure_storage.',
    fix: 'Use flutter_secure_storage package for sensitive data',
  },
];

export class MobileScanner extends BaseAgent {
  constructor() {
    super('MobileScanner', 'Mobile security scanning (OWASP Mobile Top 10)', 'mobile');
  }

  shouldRun(recon) {
    return recon?.frameworks?.some(f =>
      ['react-native', 'flutter', 'expo'].includes(f)
    ) ?? false;
  }

  async analyze(context) {
    const { rootPath, files, recon } = context;

    // Only run if mobile framework detected
    const isMobile = recon?.frameworks?.some(f =>
      ['react-native', 'flutter', 'expo'].includes(f)
    );

    // Also check for mobile-specific files
    const hasMobileFiles = files.some(f => {
      const basename = path.basename(f);
      return ['app.json', 'app.config.js', 'app.config.ts',
              'pubspec.yaml', 'AndroidManifest.xml', 'Info.plist',
              'expo-env.d.ts'].includes(basename);
    });

    if (!isMobile && !hasMobileFiles) return [];

    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.dart', '.swift', '.kt',
              '.java', '.xml', '.plist', '.json'].includes(ext);
    });

    let findings = [];
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }
    return findings;
  }
}

export default MobileScanner;
