import express from 'express';

export const app = express();

app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  return res.json({ ok: user === pass });
});

app.listen(3000);
