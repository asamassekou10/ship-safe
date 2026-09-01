import { exec } from 'child_process';
import { sanitizePathSegment } from './fs-policy.js';

export function archive(req, res) {
  const name = req.body.folder;
  const target = sanitizePathSegment(name);
  exec(`tar -czf backup.tgz ${target}`, (err) => res.sendStatus(err ? 500 : 200));
}
