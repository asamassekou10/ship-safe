const DEFAULT_STDOUT_WRITE_TIMEOUT_MS = 10_000;
const configuredStdoutWriteTimeout = Number.parseInt(process.env.SHIP_SAFE_STDOUT_TIMEOUT_MS, 10);

export const STDOUT_WRITE_TIMEOUT_MS =
  Number.isInteger(configuredStdoutWriteTimeout) && configuredStdoutWriteTimeout > 0
    ? configuredStdoutWriteTimeout
    : DEFAULT_STDOUT_WRITE_TIMEOUT_MS;

/**
 * Write a complete machine-readable report before a command exits.
 *
 * `console.log()` may return while a pipe still has buffered bytes. A direct
 * `process.exit()` can then truncate JSON or SARIF. The timeout keeps a stalled
 * downstream consumer from holding the process open forever.
 */
export function writeStdout(value) {
  return new Promise((resolve, reject) => {
    let settled = false;
    function finish(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      error ? reject(error) : resolve();
    }

    const timer = setTimeout(() => {
      const error = new Error('stdout write timed out');
      error.code = 'SHIP_SAFE_STDOUT_TIMEOUT';
      finish(error);
      process.stdout.destroy();
    }, STDOUT_WRITE_TIMEOUT_MS);

    try {
      process.stdout.write(value, finish);
    } catch (error) {
      finish(error);
    }
  });
}
