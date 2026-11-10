const http = require('http');
http.createServer((req,res)=>{
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials','true');
  res.end('ok');
}).listen(8080,'127.0.0.1');
