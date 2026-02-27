/**
 * SBOM Generator
 * ===============
 *
 * Generates Software Bill of Materials in CycloneDX JSON format.
 * Parses package.json, requirements.txt, Gemfile, go.mod, etc.
 */

import fs from 'fs';
import path from 'path';

export class SBOMGenerator {
  /**
   * Generate a CycloneDX 1.5 SBOM from the project.
   *
   * @param {string} rootPath — Project root directory
   * @returns {object} — CycloneDX JSON object
   */
  generate(rootPath) {
    const components = [];

    // ── npm/yarn/pnpm ─────────────────────────────────────────────────────────
    const pkgPath = path.join(rootPath, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

        for (const [name, version] of Object.entries(allDeps)) {
          components.push({
            type: 'library',
            name,
            version: version.replace(/^[\^~>=<]/, ''),
            purl: `pkg:npm/${name.replace('/', '%2F')}@${version.replace(/^[\^~>=<]/, '')}`,
            scope: pkg.dependencies?.[name] ? 'required' : 'optional',
          });
        }
      } catch { /* skip */ }
    }

    // ── Python requirements.txt ───────────────────────────────────────────────
    const reqPath = path.join(rootPath, 'requirements.txt');
    if (fs.existsSync(reqPath)) {
      try {
        const lines = fs.readFileSync(reqPath, 'utf-8').split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) continue;
          const match = trimmed.match(/^([a-zA-Z0-9_-]+)(?:==|>=|~=)?(.+)?$/);
          if (match) {
            components.push({
              type: 'library',
              name: match[1],
              version: match[2] || 'unspecified',
              purl: `pkg:pypi/${match[1]}@${match[2] || 'latest'}`,
              scope: 'required',
            });
          }
        }
      } catch { /* skip */ }
    }

    // ── Go modules ────────────────────────────────────────────────────────────
    const goModPath = path.join(rootPath, 'go.mod');
    if (fs.existsSync(goModPath)) {
      try {
        const content = fs.readFileSync(goModPath, 'utf-8');
        const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
        if (requireBlock) {
          const lines = requireBlock[1].split('\n');
          for (const line of lines) {
            const match = line.trim().match(/^(\S+)\s+v?(\S+)/);
            if (match) {
              components.push({
                type: 'library',
                name: match[1],
                version: match[2],
                purl: `pkg:golang/${match[1]}@${match[2]}`,
                scope: 'required',
              });
            }
          }
        }
      } catch { /* skip */ }
    }

    // ── Rust Cargo.toml ───────────────────────────────────────────────────────
    const cargoPath = path.join(rootPath, 'Cargo.toml');
    if (fs.existsSync(cargoPath)) {
      try {
        const content = fs.readFileSync(cargoPath, 'utf-8');
        const depsSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
        if (depsSection) {
          const lines = depsSection[1].split('\n');
          for (const line of lines) {
            const match = line.trim().match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
            if (match) {
              components.push({
                type: 'library',
                name: match[1],
                version: match[2],
                purl: `pkg:cargo/${match[1]}@${match[2]}`,
                scope: 'required',
              });
            }
          }
        }
      } catch { /* skip */ }
    }

    // ── Build CycloneDX BOM ───────────────────────────────────────────────────
    const bom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${this.uuid()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{
          vendor: 'ship-safe',
          name: 'ship-safe',
          version: '4.0.0',
        }],
        component: this.getProjectMetadata(rootPath),
      },
      components: components.map((c, i) => ({
        'bom-ref': `component-${i}`,
        type: c.type,
        name: c.name,
        version: c.version,
        purl: c.purl,
        scope: c.scope,
      })),
    };

    return bom;
  }

  /**
   * Generate SBOM and write to file.
   */
  generateToFile(rootPath, outputPath, format = 'cyclonedx') {
    const bom = this.generate(rootPath);
    const output = JSON.stringify(bom, null, 2);
    fs.writeFileSync(outputPath, output);
    return outputPath;
  }

  getProjectMetadata(rootPath) {
    const pkgPath = path.join(rootPath, 'package.json');
    try {
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        return {
          type: 'application',
          name: pkg.name || path.basename(rootPath),
          version: pkg.version || '0.0.0',
        };
      }
    } catch { /* skip */ }
    return {
      type: 'application',
      name: path.basename(rootPath),
      version: '0.0.0',
    };
  }

  uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }
}

export default SBOMGenerator;
