import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

export const app = express();
app.use(helmet());
app.use(rateLimit({ windowMs: 60000, max: 100 }));

app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  return res.json({ ok: user === pass });
});

app.listen(3000);
