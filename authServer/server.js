require("dotenv").config();
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


const users = [];
let refreshTokens = [];

app.get('/users', (req, res) => {
  res.json(users);
});

app.post('/register', (req, res) => {
  const username = req.body.username;
  if(username === undefined)
    return res.sendStatus(400);
  for(let user of users)
    if(user.username === req.body.username)
      return res.sendStatus(400);

  const user = {username: username};
  users.push(user);
  res.sendStatus(200);
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  if(username === undefined)
    return res.sendStatus(400);
  let user = users.filter(user => user.username === username);
  if(!user.length)
    return res.sendStatus(403);
  
  user = user[0];
  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.push(refreshToken);
  res.json({accessToken: accessToken, refreshToken: refreshToken});
});

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token);
  res.sendStatus(204);
})

app.get('/user', authenticateToken, (req, res) => {
  const name = req.user.username;
  res.send(`Hello, dear ${name}`);
})

app.post('/refresh', (req, res) => {
  const refreshToken = req.body.token;
  if(refreshToken === null)
    return res.sendStatus(401);
  if(!refreshTokens.includes(refreshToken))
    return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if(err)
      return res.sendStatus(403);
    const accessToken = generateAccessToken({username: user.username});
    res.json({accessToken: accessToken});
  });
})

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if(token == null)
    return res.sendStatus(401);
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if(err)
      return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: 20});
}

app.listen(3000, () => {
    console.log("listening on 3000");
});