import express from "express";

import cors from "cors";
import { generateRandomUserId } from "./helper";

const app = express();
app.use(express.json());

// Enable CORS for all routes
app.use(cors());

const registeredUsers: Record<string, { attestation: string }> = {};

app.post("/register", (req, res) => {
  const { attestationObject, clientDataJSON, username } = req.body;

  const userRegistrationData = { attestation: attestationObject, clientData: clientDataJSON }; // Store attestation object

  registeredUsers[username] = userRegistrationData;

  res.send(`User registered successfully with id ${username}`);
});

app.post("/login", (req, res) => {
  const { authenticatorData, username } = req.body;

  if (!registeredUsers[username]) {
    return res.status(404).send("User not registered.");
  }

  // Simulate a login process by comparing authenticator data
  if (registeredUsers[username].attestation === authenticatorData) {
    return res.send(`User logged in successfully for ${username}`);
  } else {
    return res.status(401).send("Authentication failed.");
  }
});

const PORT = process.env.PORT || 3030;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
