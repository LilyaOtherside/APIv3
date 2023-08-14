require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1/consentDB', { useNewUrlParser: true, useUnifiedTopology: true })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Define the User and Consent schemas
const UserSchema = new mongoose.Schema({
  username: String,
  password: String
});

const ConsentSchema = new mongoose.Schema({
  text: String
});

// Create models from the schemas
const User = mongoose.model('User', UserSchema);
const Consent = mongoose.model('Consent', ConsentSchema);

// Middleware for checking the JWT
const checkJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).send({ message: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send({ message: 'Invalid token' });
    }

    req.decoded = decoded;
    next();
  });
};

app.use(bodyParser.json());

// Define your endpoints
app.get('/api/v1/consent', checkJWT, (req, res) => {
  // ...
});

app.post('/api/v1/consent', checkJWT, (req, res) => {
  // ...
});

app.put('/api/v1/consent/:id', checkJWT, (req, res) => {
  // ...
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = bcrypt.hashSync(password, 8);

  const user = new User({ username, password: hashedPassword });

  user.save((err) => {
    if (err) {
      return res.status(500).send({ message: 'Error registering user' });
    }

    res.send({ message: 'User registered' });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  User.findOne({ username }, (err, user) => {
    if (err) {
      return res.status(500).send({ message: 'Error logging in' });
    }

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET);

    res.send({ token });
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));
