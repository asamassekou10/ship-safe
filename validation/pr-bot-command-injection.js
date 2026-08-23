import { exec } from 'node:child_process';

// Intentionally vulnerable maintainer fixture for live bot validation. This will not be merged.
export function runUntrustedCommand(userInput) {
  exec(`deploy ${userInput}`);
}
