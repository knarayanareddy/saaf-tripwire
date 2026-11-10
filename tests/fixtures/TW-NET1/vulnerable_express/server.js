const express = require("express");
const app = express();
app.post("/api/items", (req, res) => res.json(req.body));
app.listen(process.env.PORT || 3000, () => console.log("up"));
