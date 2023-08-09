import express from 'express';

import cors from 'cors';

const app = express();
app.use(express.json());

// Enable CORS for all routes
app.use(cors());

app.post('/register', (req, res) => {
  // Handle user registration logic here
  const newUser = req.body;
  // ... registration process ...
  res.send('User registered successfully.');
});

app.post('/login', (req, res) => {
  // Handle user login logic here
  const credentials = req.body;
  // ... login process ...
  res.send('User logged in successfully.');
});

const PORT = process.env.PORT || 3030;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
