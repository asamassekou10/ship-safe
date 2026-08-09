import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { version } = require('../../package.json');

if (typeof version !== 'string' || version.length === 0) {
  throw new Error('ship-safe package.json must define a non-empty version');
}

export const PACKAGE_VERSION = version;
