import cors from 'cors';
import express from 'express';
const app = express();
app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));
