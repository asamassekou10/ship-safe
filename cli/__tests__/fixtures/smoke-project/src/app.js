// Deliberately insecure fixture for the packaged-CLI smoke test.
// The hardcoded password below must be detected by `ship-safe scan`.
const DB_PASSWORD = "super-secret-password-123";

function connect(host) {
  return { host, DB_PASSWORD };
}

module.exports = { connect };
