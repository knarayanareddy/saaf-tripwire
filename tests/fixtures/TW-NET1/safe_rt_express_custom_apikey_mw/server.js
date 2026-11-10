const express = require('express');
const app = express();
function requireKey(req,res,next){ if (req.get('X-API-Key') !== process.env.KEY) return res.sendStatus(401); next(); }
app.use(requireKey);
app.listen(8080);
