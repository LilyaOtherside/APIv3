require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
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
app.get('/api/v1/consent', checkJWT, async (req, res) => {
  try {
    const consents = await Consent.find();
    res.send({ consents });
  } catch (err) {
    res.status(500).send({ message: 'Error retrieving consents' });
  }
});

app.post('/api/v1/consent', checkJWT, async (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).send({ message: 'Text is required' });
  }

  const consent = new Consent({ text });
  try {
    await consent.save();
    res.send({ message: 'Consent created', consent });
  } catch (err) {
    res.status(500).send({ message: 'Error creating consent' });
  }
});

app.put('/api/v1/consent/:id', checkJWT, async (req, res) => {
  const { id } = req.params;
  const { text } = req.body;

  if (!text) {
    return res.status(400).send({ message: 'Text is required' });
  }

  try {
    const consent = await Consent.findById(id);
    if (!consent) {
      return res.status(404).send({ message: 'Consent not found' });
    }

    consent.text = text;
    await consent.save();

    res.send({ message: 'Consent updated', consent });
  } catch (err) {
    res.status(500).send({ message: 'Error updating consent' });
  }
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = bcrypt.hashSync(password, 8);

  const user = new User({ username, password: hashedPassword });

  try {
    await user.save();
    res.send({ message: 'User registered' });
  } catch (err) {
    return res.status(500).send({ message: 'Error registering user' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).send({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET);

    res.send({ token });
  } catch (err) {
    return res.status(500).send({ message: 'Error logging in' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
