const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('ok'));
// app.listen(3000)  -- old: bound everywhere
app.listen(3000, '127.0.0.1');
