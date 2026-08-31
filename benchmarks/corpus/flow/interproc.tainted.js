import { runTaintedQuery } from './interproc.tainted.dao.js';

export function allocations(req, res, db) {
  const {
    threshold
  } = req.query;

  return res.json(runTaintedQuery(db, threshold));
}
