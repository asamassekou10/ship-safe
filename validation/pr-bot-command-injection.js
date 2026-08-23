import { exec } from 'node:child_process';

// Intentionally vulnerable maintainer fixture. This branch will not be merged.
export function runUntrustedCommand(userInput) {
  exec(`deploy ${userInput}`);
}
