const cors = require('cors');
const app = require('express')();
// cors() with no options would allow everything
app.use(cors({ origin: 'https://portal.example.org', credentials: true }));
