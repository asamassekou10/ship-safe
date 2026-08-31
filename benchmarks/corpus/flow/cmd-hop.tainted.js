import { exec } from 'child_process';

export function archive(req, res) {
  const name = req.body.folder;
  const target = name;
  exec(`tar -czf backup.tgz ${target}`, (err) => res.sendStatus(err ? 500 : 200));
}
