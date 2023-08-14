require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Define the User and Consent schemas
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const ConsentSchema = new mongoose.Schema({
  text: { type: String, required: true }
});

// Create models from the schemas
const User = mongoose.model('User', UserSchema);
const Consent = mongoose.model('Consent', ConsentSchema);

// Middleware for checking the JWT
const checkJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).send({ message: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: 'Invalid token' });

    req.decoded = decoded;
    next();
  });
};

app.use(bodyParser.json());

// Define your endpoints
app.get('/api/v1/consent', checkJWT, async (req, res) => {
  try {
    const consents = await Consent.find();
    res.send(consents);
  } catch (err) {
    res.status(500).send({ message: 'Error retrieving consents' });
  }
});

app.post('/api/v1/consent', checkJWT, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).send({ message: 'Text is required' });

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
  if (!text) return res.status(400).send({ message: 'Text is required' });

  try {
    const consent = await Consent.findByIdAndUpdate(id, { text }, { new: true });
    if (!consent) return res.status(404).send({ message: 'Consent not found' });

    res.send({ message: 'Consent updated', consent });
  } catch (err) {
    res.status(500).send({ message: 'Error updating consent' });
  }
});

// ... Registration and Login code ...

app.listen(3000, () => console.log('Server running on port 3000'));
