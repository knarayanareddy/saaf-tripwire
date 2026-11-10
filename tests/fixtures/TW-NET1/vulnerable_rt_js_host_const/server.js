const express = require('express');
const app = express();
const HOST = '0.0.0.0';
app.get('/x',(q,r)=>r.send('x'));
app.listen(3000, HOST);
