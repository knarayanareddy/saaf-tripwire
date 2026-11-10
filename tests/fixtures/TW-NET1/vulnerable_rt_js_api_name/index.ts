import express from 'express';
const api = express();
api.get('/x',(q,r)=>r.send('x'));
api.listen(3000);
