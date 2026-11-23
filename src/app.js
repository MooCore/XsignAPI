import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config } from './config.js';
import { router } from './routes.js';

export const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (config.frontendOrigins.includes(origin.replace(/\/$/, ''))) return callback(null, true);
    return callback(new Error('Origin is not allowed by Xsign CORS policy.'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  exposedHeaders: [],
  credentials: false,
  maxAge: 600,
}));
app.use(express.json({ limit: '1mb', strict: true }));

const presignLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many upload requests. Please slow down and try again.' },
});
const createJobLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 6,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many signing jobs from this connection. Please try again later.' },
});
const statusLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 90,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many status requests. Please slow down.' },
});

app.use('/v1/uploads/presign', presignLimiter);
app.use('/v1/signing/jobs', (req, res, next) => req.method === 'POST' ? createJobLimiter(req, res, next) : statusLimiter(req, res, next));
app.use(router);

app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint not found.' });
});

app.use((error, _req, res, _next) => {
  const status = error.statusCode || (error.message?.includes('CORS policy') ? 403 : 500);
  if (status >= 500) console.error(`API request failed (${status}).`);
  const message = status >= 500 ? 'The Xsign API encountered an unexpected error.' : error.message || 'The request could not be completed.';
  res.status(status).json({ message });
});
