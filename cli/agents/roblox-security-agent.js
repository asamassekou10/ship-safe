/**
 * Roblox / Game-Asset Supply-Chain Agent
 * ======================================
 *
 * Detects the malicious-asset supply-chain and social-engineering attack class
 * that targets Roblox / Luau developers, plus the cross-platform "ClickFix"
 * paste-and-run lure that targets developers everywhere.
 *
 * Two attack families:
 *
 *   1. GAME-ASSET SUPPLY CHAIN (Roblox Toolbox / Marketplace)
 *      A free model (footballer, anime character, game asset) is inserted into
 *      a place during prototyping. It carries obfuscated Luau that:
 *        - downloads a second-stage model at runtime via game:GetObjects /
 *          require(assetId)  (rbxassetid://...)
 *        - enables HttpService for exfiltration / C2
 *        - removes an internal version/detection guard before running it
 *        - stores its payload in an INSTANCE ATTRIBUTE (not script source) so
 *          source-only scanners never see it. In a Rojo-managed repo this
 *          serializes to a base64 <BinaryString name="AttributesSerialize">
 *          blob inside the .rbxmx / .rbxlx XML.
 *
 *   2. CLICKFIX SOCIAL ENGINEERING (cross-platform)
 *      A fake error / CAPTCHA dialog ("Error 501", "verify you are human")
 *      instructs the developer to copy text and run it via a keystroke
 *      sequence (Ctrl+C -> Shift+F5 -> Ctrl+V -> Enter, or Win+R). Lures show
 *      up in HTML overlays, READMEs, docs, and embedded UI text.
 *
 * Scans:
 *   - .lua / .luau source files
 *   - .rbxmx / .rbxlx XML model/place files (script <ProtectedString> source
 *     AND decoded instance attributes)
 *   - any text/markdown/HTML file (ClickFix lure only)
 *
 * Maps to: CWE-506 (Embedded Malicious Code), CWE-829 (Untrusted Functionality),
 *          CWE-94 (Code Injection), CWE-1357 (Reliance on Insufficiently
 *          Trustworthy Component). Class: Supply Chain.
 */

import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// LUAU SOURCE PATTERNS (run on .lua/.luau and decoded .rbxmx script source)
// =============================================================================

const LUAU_PATTERNS = [
  {
    regex: /game\s*:\s*GetObjects\s*\(\s*['"]rbxassetid:\/\//gi,
    rule: 'ROBLOX_RUNTIME_ASSET_FETCH',
    title: 'Runtime asset injection via GetObjects(rbxassetid://)',
    severity: 'critical',
    description: 'Script downloads an external model from the Roblox CDN at runtime and inserts it into the place. This bypasses any local file inspection and is the delivery mechanism for second-stage backdoor models. Legitimate games almost never fetch assets this way.',
    cwe: 'CWE-829',
    fix: 'Remove the runtime GetObjects call. Bundle and review any required models in source; never insert assets fetched by id at runtime.',
  },
  {
    regex: /\brequire\s*\(\s*\d{6,}\s*\)/g,
    rule: 'ROBLOX_REQUIRE_BY_ASSET_ID',
    title: 'require() by numeric asset id',
    severity: 'critical',
    description: 'Loading a ModuleScript by numeric asset id pulls and executes code from an external, mutable asset the developer does not control. The asset can be re-uploaded with a malicious payload after review.',
    cwe: 'CWE-829',
    fix: 'Replace require(assetId) with a require of a local, version-controlled ModuleScript.',
  },
  {
    regex: /HttpService[^=\n]*\bHttpEnabled\s*=\s*true/g,
    rule: 'ROBLOX_HTTP_ENABLE',
    title: 'HttpService.HttpEnabled set to true in a script',
    severity: 'high',
    dualUse: true,
    description: 'A script enables outbound HTTP at runtime. This is required for data exfiltration, C2 callbacks, or webhook logging of stolen session data, and should be a deliberate place setting, not something a script flips on.',
    cwe: 'CWE-829',
    confidence: 'medium',
    fix: 'Do not enable HttpService from a script. If outbound HTTP is genuinely required, enable it explicitly in Game Settings and audit every request site.',
  },
  {
    regex: /\bloadstring\s*\(/g,
    rule: 'ROBLOX_LOADSTRING',
    title: 'Dynamic code execution via loadstring()',
    severity: 'high',
    dualUse: true,
    description: 'loadstring compiles and runs a string as Luau at runtime — the core primitive for executing a decoded/obfuscated payload. It is disabled by default in Roblox for this reason.',
    cwe: 'CWE-94',
    fix: 'Remove loadstring. Move logic into reviewed source rather than runtime-compiled strings.',
  },
  {
    // Start-of-statement assignment to a built-in global only. Excludes
    // `local Instance = ...`, member assigns (`x.Instance =`), and `==`.
    // `vector` is intentionally omitted — it is now a real Luau library and a
    // common variable name, so flagging it is too noisy.
    regex: /^\s*(?:Instance|CFrame|game|workspace)\s*=\s*(?!=)/g,
    rule: 'ROBLOX_GLOBAL_SHADOW',
    title: 'Assignment to a Roblox global (Instance/CFrame/game/workspace)',
    severity: 'medium',
    description: 'The script reassigns a built-in Roblox global at statement level. In the observed attack the decoded payload string was assigned to the global Instance constructor to smuggle it past readers and into an execution context. Legitimate code does not reassign these globals.',
    cwe: 'CWE-94',
    confidence: 'low',
    fix: 'Never assign to Instance, CFrame, game, or workspace. Use locals. Treat any such assignment in third-party code as malicious.',
  },
  {
    regex: /:\s*sub\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\.\.\s*\w+/g,
    rule: 'ROBLOX_STRING_REVERSE_DECODE',
    title: 'String-reversal / character-by-character decode loop',
    severity: 'medium',
    description: 'A character-by-character string-building loop (sub(i,i) .. acc) is a common, lightweight obfuscation used to hide a payload backwards so it does not appear in string searches. Combined with an attribute read it reconstructs an off-script payload.',
    cwe: 'CWE-506',
    confidence: 'medium',
    fix: 'Inspect what the decoded string contains. Obfuscated decoders in third-party assets are almost always malicious.',
  },
  {
    regex: /FindFirstChild\s*\(\s*['"]Version[:.]/gi,
    rule: 'ROBLOX_GUARD_DESTROY',
    title: 'Lookup of an internal Version guard (likely to Destroy it)',
    severity: 'medium',
    description: 'Searching for an internal "Version" object, typically to Destroy() it, matches the technique of removing a downloaded model\'s built-in version-check / detection guard before it runs.',
    cwe: 'CWE-829',
    confidence: 'medium',
    fix: 'Verify why a script is locating and destroying a version guard. In inserted assets this disables tamper detection.',
  },
];

// Lua source that reads an instance attribute and feeds it to a decode loop —
// the off-script payload pattern. Detected as a co-occurrence in _scanLuaSource.
const ATTR_READ_REGEX = /GetAttribute\s*\(\s*['"][^'"]+['"]\s*\)/;

// "Definite" malicious IOCs. When any of these are present in the same file,
// dual-use findings (HttpEnabled, loadstring) are treated as malicious too.
const DEFINITE_RULES = new Set([
  'ROBLOX_RUNTIME_ASSET_FETCH',
  'ROBLOX_REQUIRE_BY_ASSET_ID',
  'ROBLOX_ATTRIBUTE_PAYLOAD_LOADER',
]);

// =============================================================================
// CLICKFIX LURE (run on any text/markdown/HTML file)
// =============================================================================

// Error/CAPTCHA framing near an instruction to copy text and run it via keys.
const CLICKFIX_FRAMING = /(?:error\s*\d{3}|verify\s+(?:you\s+are|that\s+you'?re)\s+(?:a\s+)?human|i'?m\s+not\s+a\s+robot|something\s+went\s+wrong\s+with\s+this)/i;
const CLICKFIX_ACTION = /(?:ctrl\s*\+\s*c\b[\s\S]{0,160}ctrl\s*\+\s*v|win\s*\+\s*r|shift\s*\+\s*f5|command\s+bar|paste\s+(?:it|this|the\s+(?:text|code)))/i;

const SCANNABLE_LUAU_EXT = new Set(['.lua', '.luau']);
const SCANNABLE_RBX_EXT = new Set(['.rbxmx', '.rbxlx']);
const CLICKFIX_EXT = new Set(['.lua', '.luau', '.rbxmx', '.rbxlx', '.html', '.htm', '.md', '.txt', '.json', '.js', '.ts']);

// =============================================================================
// AGENT
// =============================================================================

export class RobloxSecurityAgent extends BaseAgent {
  constructor() {
    super(
      'RobloxSecurityAgent',
      'Detects malicious Roblox/Luau Toolbox assets (runtime asset injection, attribute-stored payloads, obfuscated loaders) and cross-platform ClickFix paste-and-run lures',
      'supply-chain'
    );
  }

  /**
   * Run when the project shows any Roblox/Luau signal, OR always for the
   * ClickFix lure (which is platform-agnostic). We gate the expensive Roblox
   * passes per-file by extension, so running broadly is cheap.
   */
  shouldRun() {
    return true;
  }

  async analyze(context) {
    const files = this.getFilesToScan(context);
    const findings = [];

    for (const file of files) {
      const ext = path.extname(file).toLowerCase();

      if (SCANNABLE_LUAU_EXT.has(ext)) {
        findings.push(...this._scanLuaSource(file, this.readFile(file), null, 'firstparty'));
      } else if (SCANNABLE_RBX_EXT.has(ext)) {
        findings.push(...this._scanRbxXml(file));
      }

      if (CLICKFIX_EXT.has(ext)) {
        findings.push(...this._scanClickFix(file));
      }
    }

    return findings;
  }

  // ── Luau source ────────────────────────────────────────────────────────────

  /**
   * Scan Luau source text. `virtualFile` lets .rbxmx-embedded script source be
   * reported against the containing file with a path hint.
   */
  _scanLuaSource(file, content, pathHint = null, trustLevel = 'firstparty') {
    if (!content) return [];
    const findings = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (this.isSuppressed(line)) continue;

      for (const p of LUAU_PATTERNS) {
        p.regex.lastIndex = 0;
        let match;
        while ((match = p.regex.exec(line)) !== null) {
          findings.push(this._finding(file, i + 1, match, p, pathHint));
          if (!p.regex.global) break;
        }
      }
    }

    // Off-script payload tell: an attribute read AND a reverse-decode loop in
    // the same script. Higher severity than either alone.
    if (ATTR_READ_REGEX.test(content) && /:\s*sub\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\.\./.test(content)) {
      findings.push(createFinding({
        file,
        line: 1,
        severity: 'high',
        category: 'supply-chain',
        rule: 'ROBLOX_ATTRIBUTE_PAYLOAD_LOADER',
        title: 'Off-script payload loader (attribute read + decode loop)',
        description: 'Script reads an instance attribute and reconstructs it through a decode loop. This is the off-script payload technique: the malicious string lives in an instance attribute (invisible to source scanners) and is decoded at runtime.' + (pathHint ? ` Instance path: ${pathHint}.` : ''),
        matched: 'GetAttribute(...) + reverse decode',
        confidence: 'high',
        cwe: 'CWE-506',
        fix: 'Treat as malicious. Inspect the attribute value, remove the loader, and delete the asset it came from.',
      }));
    }

    // ── Dual-use gating ──────────────────────────────────────────────────────
    // HttpEnabled / loadstring are legitimate in author-written server code but
    // malicious in inserted assets. Elevate them only when the source is
    // untrusted (came from a .rbxmx/.rbxlx asset) or co-occurs with a definite
    // malicious IOC; otherwise soften so we don't drown real games in noise.
    const DUAL_USE = new Set(['ROBLOX_HTTP_ENABLE', 'ROBLOX_LOADSTRING']);
    const hasDefinite = findings.some(f => DEFINITE_RULES.has(f.rule));
    const untrusted = trustLevel === 'untrusted';
    const isServer = !pathHint && /\.server\.luau?$/i.test(file);

    for (const f of findings) {
      if (!DUAL_USE.has(f.rule)) continue;
      if (untrusted || hasDefinite) {
        f.confidence = 'high';
        f.description += untrusted
          ? ' This came from an inserted asset (.rbxmx/.rbxlx), where enabling HTTP / runtime code execution is a strong malicious signal.'
          : ' This file also contains a definite malicious indicator, so this dual-use call is treated as part of the attack.';
      } else {
        f.severity = 'medium';
        f.confidence = isServer ? 'low' : 'medium';
        f.description += isServer
          ? ' Found in an author-written server script with no other malicious indicators — likely intentional, but verify.'
          : ' No other malicious indicators in this file — verify this use is intentional.';
      }
    }

    return findings;
  }

  // ── Roblox XML model/place files ─────────────────────────────────────────────

  _scanRbxXml(file) {
    const content = this.readFile(file);
    if (!content) return [];
    const findings = [];

    // 1. Embedded script source lives in <ProtectedString name="Source">...
    const sourceRe = /<ProtectedString\s+name="Source">([\s\S]*?)<\/ProtectedString>/g;
    let m;
    while ((m = sourceRe.exec(content)) !== null) {
      const decoded = this._xmlUnescape(m[1]);
      const lineNum = content.slice(0, m.index).split('\n').length;
      findings.push(...this._scanLuaSource(file, decoded, `${path.basename(file)} embedded Script @ line ${lineNum}`, 'untrusted'));
    }

    // 2. Instance attributes are serialized as base64 in
    //    <BinaryString name="AttributesSerialize">...</BinaryString>.
    //    Decode and inspect the readable strings for payload IOCs.
    const attrRe = /<BinaryString\s+name="AttributesSerialize">([\s\S]*?)<\/BinaryString>/g;
    while ((m = attrRe.exec(content)) !== null) {
      const lineNum = content.slice(0, m.index).split('\n').length;
      const decoded = this._b64DecodeReadable(m[1]);
      if (!decoded) continue;
      findings.push(...this._scanAttributeBlob(file, decoded, lineNum));
    }

    return findings;
  }

  /**
   * Inspect a decoded attribute blob for payload IOCs, including the reversed
   * form (payloads are often stored backwards).
   */
  _scanAttributeBlob(file, decoded, lineNum) {
    const findings = [];
    const reversed = decoded.split('').reverse().join('');
    const haystacks = [decoded, reversed];

    const checks = [
      { re: /rbxassetid:\/\/\d+/i, why: 'an external asset id' },
      { re: /HttpEnabled\s*=\s*true/i, why: 'an HttpService enable' },
      { re: /loadstring\s*\(/i, why: 'a loadstring call' },
      { re: /GetObjects\s*\(/i, why: 'a runtime GetObjects call' },
    ];

    for (const h of haystacks) {
      for (const c of checks) {
        if (c.re.test(h)) {
          findings.push(createFinding({
            file,
            line: lineNum,
            severity: 'critical',
            category: 'supply-chain',
            rule: 'ROBLOX_ATTRIBUTE_PAYLOAD',
            title: 'Executable payload hidden in an instance attribute',
            description: `A serialized instance attribute contains ${c.why}${h === reversed ? ' (stored reversed)' : ''}. Attribute-stored payloads are invisible to source-only scanners and are the technique used to smuggle code past Toolbox moderation.`,
            matched: (h.match(c.re) || [''])[0].slice(0, 80),
            confidence: 'high',
            cwe: 'CWE-506',
            fix: 'Delete the asset. Attributes carrying code/asset references on physics or appearance objects are malicious.',
          }));
          return findings; // one finding per blob is enough signal
        }
      }
    }
    return findings;
  }

  // ── ClickFix lure ────────────────────────────────────────────────────────────

  _scanClickFix(file) {
    const content = this.readFile(file);
    if (!content) return [];
    // Match within a sliding window so framing + action must be near each other.
    if (!CLICKFIX_FRAMING.test(content)) return [];
    const idx = content.search(CLICKFIX_FRAMING);
    const window = content.slice(Math.max(0, idx - 200), idx + 600);
    if (!CLICKFIX_ACTION.test(window)) return [];

    const lineNum = content.slice(0, idx).split('\n').length;
    return [createFinding({
      file,
      line: lineNum,
      severity: 'high',
      category: 'supply-chain',
      rule: 'CLICKFIX_PASTE_RUN',
      title: 'ClickFix paste-and-run social-engineering lure',
      description: 'Text presents a fake error or human-verification prompt next to an instruction to copy content and run it via a keystroke sequence (e.g. Ctrl+C -> Ctrl+V -> Enter, Win+R, command bar). This is the ClickFix lure pattern. No legitimate tool asks a developer to paste and run code to recover from an error.',
      matched: (content.slice(idx).match(CLICKFIX_FRAMING) || [''])[0].slice(0, 80),
      confidence: 'medium',
      cwe: 'CWE-1357',
      fix: 'Do not run the instructed code. Remove this lure. Treat the asset/page that rendered it as compromised.',
    })];
  }

  // ── helpers ──────────────────────────────────────────────────────────────────

  _finding(file, line, match, p, pathHint) {
    return createFinding({
      file,
      line,
      column: (match.index || 0) + 1,
      severity: p.severity,
      category: 'supply-chain',
      rule: p.rule,
      title: p.title,
      description: p.description + (pathHint ? ` Source: ${pathHint}.` : ''),
      matched: match[0].slice(0, 120),
      confidence: p.confidence || 'high',
      cwe: p.cwe || null,
      owasp: p.owasp || null,
      fix: p.fix || null,
    });
  }

  _xmlUnescape(s) {
    return s
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&amp;/g, '&');
  }

  /**
   * Decode base64 and keep only the readable (printable) runs, so we can
   * regex-match strings embedded in the binary attribute container.
   */
  _b64DecodeReadable(b64) {
    try {
      const buf = Buffer.from(b64.replace(/\s+/g, ''), 'base64');
      if (!buf.length) return null;
      // Replace non-printable bytes with spaces; keep tab/newline.
      let out = '';
      for (const byte of buf) {
        out += (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126))
          ? String.fromCharCode(byte)
          : ' ';
      }
      return out;
    } catch {
      return null;
    }
  }
}

export default RobloxSecurityAgent;
