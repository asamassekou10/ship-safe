/**
 * ModelScanAgent — ML model supply-chain scanner
 * ==============================================
 *
 * ML model weights are executable. The pickle serialization format — the
 * default for PyTorch (`.pt/.pth/.ckpt/.bin`), joblib, dill, and raw
 * `.pkl` — runs arbitrary code at load time via the REDUCE/GLOBAL opcodes.
 * Malicious models on Hugging Face have repeatedly used this to execute code
 * the moment a developer calls `torch.load()` / `pickle.load()`, and have
 * evaded the hub's own PickleScan (which itself carries CVSS-9.3 bypasses,
 * CVE-2025-10155/56/57).
 *
 * This agent opens model weight files that other agents skip (they are binary
 * and over the 1 MB text cap) and statically inspects the byte stream for the
 * pickle opcodes and dangerous global references used for code execution —
 * without ever unpickling. It also flags unsafe source-level loaders and
 * archive-wrapping used to dodge scanners.
 *
 * Maps to: CWE-502 (Deserialization of Untrusted Data), CWE-506 (Embedded
 *          Malicious Code). Class: Supply Chain.
 */

import fs from 'fs';
import path from 'path';
import fg from 'fast-glob';
import { BaseAgent, createFinding } from './base-agent.js';
import { SKIP_DIRS } from '../utils/patterns.js';

// Pickle-based model formats — these deserialize via pickle and can run code.
const PICKLE_EXTS = new Set(['.pkl', '.pickle', '.pt', '.pth', '.ckpt', '.bin', '.joblib', '.dill', '.model', '.pt2', '.pak']);
// Formats that are NOT pickle-based; safetensors is the safe target we steer to.
const SAFE_EXTS = new Set(['.safetensors', '.gguf', '.onnx', '.npz']);
const MODEL_GLOB = ['**/*.{pkl,pickle,pt,pth,ckpt,bin,joblib,dill,model,pt2,pak,safetensors}'];

// Max bytes to inspect from each end of a (potentially multi-GB) weight file.
const HEAD_BYTES = 8 * 1024 * 1024;
const TAIL_BYTES = 2 * 1024 * 1024;
const MAX_MODEL_BYTES = 5 * 1024 * 1024 * 1024; // skip absurdly large (>5GB)

// Dangerous callables that appear as newline/opcode-delimited ASCII inside a
// pickle GLOBAL / STACK_GLOBAL. High-signal, low false-positive.
const DANGEROUS = [
  'os\nsystem', 'posix\nsystem', 'nt\nsystem', 'os\npopen', 'os\nexecv', 'os\nspawnl',
  'subprocess', 'builtins\nexec', 'builtins\neval', '__builtin__\neval', '__builtin__\nexec',
  'pty\nspawn', 'runpy', 'socket\nsocket', 'commands\ngetoutput', 'webbrowser\nopen',
  'importlib\nimport_module', 'operator\nattrgetter',
];

// Archive magics used to wrap a pickle so a byte-scanner mis-parses it.
const SEVENZIP_MAGIC = Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
const RAR_MAGIC = Buffer.from([0x52, 0x61, 0x72, 0x21]);
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]); // PyTorch .pt is a zip of data.pkl

// Source-level unsafe loaders.
const SOURCE_PATTERNS = [
  {
    regex: /trust_remote_code\s*=\s*True/g,
    rule: 'RAG_TRUST_REMOTE_CODE',
    title: 'Model loaded with trust_remote_code=True',
    severity: 'high',
    description: 'The model loader allows executable Python code from the remote model repository.',
    cwe: 'CWE-829',
    fix: 'Set trust_remote_code=False and use a model whose code has been reviewed and pinned.',
  },
  {
    regex: /torch\s*\.\s*load\s*\((?![^)]*weights_only\s*=\s*True)/g,
    rule: 'MODEL_TORCH_LOAD_UNSAFE',
    title: 'torch.load() without weights_only=True',
    severity: 'high',
    description: 'torch.load() unpickles by default, executing arbitrary code embedded in the checkpoint. Set weights_only=True (PyTorch ≥ 2.6 defaults to it) or load safetensors.',
    cwe: 'CWE-502',
    fix: 'Pass weights_only=True to torch.load(), or convert the checkpoint to safetensors.',
  },
  {
    regex: /(?:pickle|cPickle|dill|joblib)\s*\.\s*load[s]?\s*\(/g,
    rule: 'MODEL_PICKLE_LOAD_SOURCE',
    title: 'pickle/joblib/dill load on a model artifact',
    severity: 'medium',
    description: 'Loading a model via pickle/joblib/dill deserializes untrusted data and can execute code. Prefer safetensors for weights.',
    cwe: 'CWE-502',
    confidence: 'medium',
    fix: 'Use safetensors for model weights; only unpickle artifacts you produced and trust.',
  },
];

export class ModelScanAgent extends BaseAgent {
  constructor() {
    super(
      'ModelScanAgent',
      'Detects code-execution payloads in ML model weight files (pickle) and unsafe model loaders',
      'supply-chain'
    );
  }

  shouldRun() {
    return true; // cheap: exits immediately when no model files are present
  }

  async analyze(context) {
    const { rootPath } = context;
    const findings = [];

    // 1. Binary weight files (discovered independently — these are skipped by
    //    the shared text-file discovery due to size/extension).
    const modelFiles = await fg(MODEL_GLOB, {
      cwd: rootPath,
      absolute: true,
      onlyFiles: true,
      dot: false,
      ignore: Array.from(SKIP_DIRS).map((d) => `**/${d}/**`),
      followSymbolicLinks: false,
    });
    for (const file of modelFiles) {
      findings.push(...this._scanModelFile(file));
    }

    // 2. Source-level unsafe loaders.
    for (const file of this.getFilesToScan(context)) {
      const ext = path.extname(file).toLowerCase();
      if (ext === '.py' || ext === '.ipynb') {
        findings.push(...this.scanFileWithPatterns(file, SOURCE_PATTERNS));
        findings.push(...this._scanRemoteModelSources(file));
      }
    }

    return findings;
  }

  _scanRemoteModelSources(file) {
    const content = this.readFile(file);
    if (!content) return [];

    const findings = [];
    const mutableDownloads = [];
    const hubCalls = this._findCalls(
      content,
      /\b(?:[A-Za-z_][\w]*\.)*(from_pretrained|snapshot_download|hf_hub_download)\s*\(/g
    );

    for (const call of hubCalls) {
      const reference = this._modelReference(call.args);
      if (!reference || this._isLocalReference(reference, file)) continue;
      if (this._hasPinnedRevision(call.args)) continue;

      mutableDownloads.push(call);
      findings.push(createFinding({
        file,
        line: this._lineAt(content, call.index),
        severity: 'high',
        category: 'supply-chain',
        rule: 'MODEL_MUTABLE_REMOTE_REFERENCE',
        title: 'Model download uses a mutable remote reference',
        description: `The ${call.name} call downloads model code or weights without pinning revision to a full commit hash. The reviewed artifact can change later.`,
        matched: `${call.name} without commit revision`,
        confidence: 'high',
        cwe: 'CWE-829',
        fix: 'Set revision to the full commit hash of the reviewed model repository.',
      }));
    }

    const rawCalls = this._findCalls(
      content,
      /\b((?:requests\.(?:get|post)|urllib\.request\.(?:urlopen|urlretrieve)|wget\.download|torch\.hub\.download_url_to_file))\s*\(/g
    );
    for (const call of rawCalls) {
      const url = call.args.match(/["'](https?:\/\/[^"']+)["']/i)?.[1];
      if (!url || !/\.(?:pkl|pickle|pt|pth|ckpt|bin|safetensors|gguf|onnx)(?:[?#]|$)/i.test(url)) continue;
      if (this._hasImmutableUrl(url) || this._hasChecksumVerification(content, call)) continue;

      mutableDownloads.push(call);
      findings.push(createFinding({
        file,
        line: this._lineAt(content, call.index),
        severity: 'high',
        category: 'supply-chain',
        rule: 'MODEL_MUTABLE_RAW_URL',
        title: 'Model artifact URL has no immutable revision or checksum',
        description: 'A model artifact is downloaded from a mutable URL without a commit-pinned path or checksum verification.',
        matched: 'model URL without revision or checksum',
        confidence: 'high',
        cwe: 'CWE-494',
        fix: 'Use an immutable commit-pinned URL and verify the artifact SHA-256 before loading it.',
      }));
    }

    const pickleDownload = mutableDownloads.find((call) => this._feedsPickleLoader(content, call));
    if (pickleDownload) {
      findings.push(createFinding({
        file,
        line: this._lineAt(content, pickleDownload.index),
        severity: 'critical',
        category: 'supply-chain',
        rule: 'MODEL_MUTABLE_DOWNLOAD_PICKLE_LOAD',
        title: 'Mutable model download is loaded through pickle',
        description: 'This source downloads a mutable remote model artifact and later loads a pickle-capable format, allowing the remote artifact to become code execution.',
        matched: 'mutable download followed by pickle load',
        confidence: 'high',
        cwe: 'CWE-502',
        fix: 'Pin and verify the download, use safetensors, and avoid pickle-capable loaders for remote artifacts.',
      }));
    }

    return findings;
  }

  _findCalls(content, pattern) {
    const calls = [];
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const open = pattern.lastIndex - 1;
      let depth = 1;
      let quote = null;
      let escaped = false;
      let end = open + 1;

      for (; end < content.length && depth > 0; end++) {
        const char = content[end];
        if (quote) {
          if (escaped) escaped = false;
          else if (char === '\\') escaped = true;
          else if (char === quote) quote = null;
          continue;
        }
        if (char === '"' || char === "'") quote = char;
        else if (char === '(') depth++;
        else if (char === ')') depth--;
      }
      if (depth === 0) {
        const linePrefix = content.slice(content.lastIndexOf('\n', match.index) + 1, match.index);
        calls.push({
          name: match[1],
          index: match.index,
          end,
          assignedTo: linePrefix.match(/\b([A-Za-z_]\w*)\s*=\s*$/)?.[1] || null,
          args: content.slice(open + 1, end - 1),
        });
      }
    }
    return calls;
  }

  _feedsPickleLoader(content, call) {
    const loaders = String.raw`(?:torch\.load|pickle\.load|joblib\.load|dill\.load)`;
    if (call.assignedTo) {
      const variable = call.assignedTo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (new RegExp(String.raw`\b${loaders}\s*\(\s*${variable}\b`, 'i').test(content.slice(call.end))) {
        return true;
      }
    }

    const prefix = content.slice(Math.max(0, call.index - 120), call.index);
    return new RegExp(String.raw`\b${loaders}\s*\(\s*$`, 'i').test(prefix);
  }

  _modelReference(args) {
    return args.match(/\b(?:pretrained_model_name_or_path|repo_id)\s*=\s*["']([^"']+)["']/i)?.[1]
      || args.match(/^\s*["']([^"']+)["']/)?.[1]
      || null;
  }

  _isLocalReference(reference, sourceFile) {
    if (/^(?:\.{0,2}[\\/]|~[\\/]|[A-Za-z]:[\\/]|file:\/\/)/i.test(reference)) return true;
    if (path.isAbsolute(reference)) return true;
    if (/^(?:models?|checkpoints?|weights?|artifacts?|outputs?)[\\/]/i.test(reference)) return true;
    if (/\.(?:pkl|pickle|pt|pth|ckpt|bin|safetensors|gguf|onnx)$/i.test(reference)) return true;
    return fs.existsSync(path.resolve(path.dirname(sourceFile), reference));
  }

  _hasPinnedRevision(args) {
    const revision = args.match(/\brevision\s*=\s*["']([0-9a-f]+)["']/i)?.[1];
    return Boolean(revision && (revision.length === 40 || revision.length === 64));
  }

  _hasImmutableUrl(url) {
    return /\/(?:resolve|blob)\/(?:[0-9a-f]{40}|[0-9a-f]{64})\//i.test(url)
      || /[?&](?:revision|rev)=(?:[0-9a-f]{40}|[0-9a-f]{64})(?:&|$)/i.test(url);
  }

  _hasChecksumVerification(content, call) {
    if (call.name === 'torch.hub.download_url_to_file') {
      return /\bhash_prefix\s*=\s*["'][0-9a-f]{8,64}["']/i.test(call.args);
    }
    if (!call.assignedTo) return false;

    const variable = call.assignedTo.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const following = content.slice(call.end, call.end + 1200);
    const hashesDownloadedBytes = new RegExp(
      String.raw`hashlib\.sha256\s*\(\s*${variable}\.(?:content|raw\.read\s*\(\s*\))\s*\)`,
      'i'
    ).test(following);
    return hashesDownloadedBytes && /["'][0-9a-f]{64}["']/i.test(following);
  }

  _lineAt(content, index) {
    return content.slice(0, index).split('\n').length;
  }

  _scanModelFile(file) {
    const ext = path.extname(file).toLowerCase();
    if (SAFE_EXTS.has(ext)) return []; // safetensors et al. cannot execute on load

    let size;
    try { size = fs.statSync(file).size; } catch { return []; }
    if (size === 0 || size > MAX_MODEL_BYTES) return [];

    const buf = this._readHeadTail(file, size);
    if (!buf) return [];

    // Scanner-evasion: a model-named file wrapped in 7z/rar.
    if (buf.subarray(0, 6).equals(SEVENZIP_MAGIC) || buf.subarray(0, 4).equals(RAR_MAGIC)) {
      return [createFinding({
        file, line: 0, severity: 'high', category: 'supply-chain',
        rule: 'MODEL_EVASION_ARCHIVE',
        title: 'Model file wrapped in an unusual archive (scanner evasion)',
        description: 'A model-named file is a 7z/RAR archive. This is a known technique for smuggling a malicious pickle past model scanners that only inspect the outer file.',
        matched: ext, confidence: 'medium', cwe: 'CWE-506',
        fix: 'Do not load this file. Obtain the model from a trusted source in safetensors format.',
      })];
    }

    const isZip = buf.subarray(0, 4).equals(ZIP_MAGIC);       // PyTorch container
    const isPickle = this._looksLikePickle(buf);
    // Dedicated pickle extensions are always treated as pickle; ambiguous
    // extensions (.bin) require a positive pickle/zip signal to avoid noise.
    const treatAsPickle = isPickle || isZip || (PICKLE_EXTS.has(ext) && ext !== '.bin');
    if (!treatAsPickle) return [];

    const hit = this._findDangerous(buf);
    if (hit) {
      return [createFinding({
        file, line: 0, severity: 'critical', category: 'supply-chain',
        rule: 'MODEL_PICKLE_CODE_EXECUTION',
        title: 'Code-execution payload embedded in a model file',
        description: `The pickle stream references \`${hit}\`, a callable used to execute commands or code at load time. Loading this model (torch.load / pickle.load) would run attacker-controlled code.`,
        matched: hit, confidence: 'high', cwe: 'CWE-506',
        fix: 'Quarantine and do not load this model. Re-obtain from a trusted source as safetensors; report the artifact to the hub it came from.',
      })];
    }

    return [createFinding({
      file, line: 0, severity: 'high', category: 'supply-chain',
      rule: 'MODEL_UNSAFE_PICKLE_FORMAT',
      title: 'Pickle-serialized model file (executes code on load)',
      description: 'This model is stored in a pickle-based format, which can execute arbitrary code when deserialized. No known-dangerous callable was found in the inspected region, but the format itself is unsafe for untrusted models.',
      matched: ext, confidence: 'medium', cwe: 'CWE-502',
      fix: 'Convert to safetensors, or load only with a restricted unpickler / weights_only=True.',
    })];
  }

  /** Pickle protocol 2–5 header (\x80 + proto byte), or classic pickle opcode start. */
  _looksLikePickle(buf) {
    if (buf.length >= 2 && buf[0] === 0x80 && buf[1] >= 0x02 && buf[1] <= 0x05) return true;
    // Protocol 0/1 streams start with a printable opcode like '(', '}', ']', 'c'.
    const c = buf[0];
    return c === 0x28 || c === 0x7d || c === 0x5d || c === 0x63;
  }

  _findDangerous(buf) {
    for (const needle of DANGEROUS) {
      if (buf.includes(needle)) return needle.replace(/\n/g, '.');
    }
    return null;
  }

  _readHeadTail(file, size) {
    let fd;
    try {
      fd = fs.openSync(file, 'r');
      if (size <= HEAD_BYTES + TAIL_BYTES) {
        const whole = Buffer.allocUnsafe(size);
        fs.readSync(fd, whole, 0, size, 0);
        return whole;
      }
      const head = Buffer.allocUnsafe(HEAD_BYTES);
      const tail = Buffer.allocUnsafe(TAIL_BYTES);
      fs.readSync(fd, head, 0, HEAD_BYTES, 0);
      fs.readSync(fd, tail, 0, TAIL_BYTES, size - TAIL_BYTES);
      return Buffer.concat([head, tail]);
    } catch {
      return null;
    } finally {
      if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* */ } }
    }
  }
}

export default ModelScanAgent;
