import { runGuardedQuery } from './interproc.guarded.dao.js';

export function allocations(req, res, db) {
  const threshold = parseInt(req.query.threshold, 10);
  return res.json(runGuardedQuery(db, threshold));
}
