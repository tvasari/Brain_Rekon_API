const express = require('express');
const bcrypt = require('bcrypt-nodejs');
const cors = require('cors');
const knex = require('knex');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");

const register = require('./controllers/register.js');
const signin = require('./controllers/signin.js');
const profile = require('./controllers/profile.js');
const image = require('./controllers/image.js');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
const db = knex({
  client: 'pg',
  connection: {
    connectionString: process.env.DATABASE_URL,
    ssl: true
  }
});

const signinLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5,
  message: JSON.stringify("Too many log-in attempts, retry in 1 minute")
});

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cors());
app.use("/signin", signinLimiter);

app.get('/', (req, res) => {res.send('it is working');})
app.get('/confirmation/:token', (req, res) => {
  jwt.verify(req.params.token, 'secret4algorithm', (err, verifiedJwt) => {
    if (err) {
      res.send(err.message)
    } else {
      db('login').where('email', '=', verifiedJwt.user).update({confirmed: true}).then(user => res.send(user));
    }
    return res.redirect('https://brain-rekon.herokuapp.com/signin');
  }); 
})
app.post('/signin', (req, res) => { signin.handleSignIn(req, res, db, bcrypt) })
app.post('/register', (req, res) => { register.handleRegister(req, res, db, bcrypt, jwt) }) //dependency injection
app.get('/profile/:id', (req, res) => { profile.handleProfile(req, res, db) })
app.put('/image', (req, res) => { image.handleImage(req, res, db) })
app.post('/imageurl', (req, res) => { image.handleApiCall(req, res) })

app.listen(process.env.PORT || 3001, () => {
	console.log(`app is running on port ${process.env.PORT}`)
})