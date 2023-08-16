import express from "express";
import cors from "cors";
import crypto from "crypto";
import { base64URLDecode, verifyAuthenticatorDataAndAttestation, verifyClientDataJSON } from "./helper";

const app = express();
app.use(express.json());

// Enable CORS for all routes
app.use(cors());

const registeredUsers: Record<string, { attestation: string; clientData: string }> = {
  "12": {
    attestation:
      "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJ3jImqEXLFLrkNRfrOncBR9P3OopQECAyYgASFYIEJP95sicsTsvFh0Fxfql2DjoTD5z1GKDGCdTIEJS+piIlggqLIX3pbhZlOhcYhVI4EXb1E2tl0guLS/UTuRaytKCdo=",
    clientData:
      "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZFQzODU3X3giLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
  },
};

const challengeStorage = new Map();

app.get("/generate-challenge", (req, res) => {
  const challenge = crypto.randomBytes(32).toString("base64");
  const challengeId = crypto.randomBytes(16).toString("hex");

  challengeStorage.set(challengeId, challenge);
  res.json({ challengeId, challenge });
});

app.post("/register", (req, res) => {
  const { attestationObject, clientDataJSON, username, challengeId } = req.body;
  const storedChallenge = challengeStorage.get(challengeId);

  if (!storedChallenge) {
    return res.status(400).send("Invalid challenge ID");
  }

  if (!verifyClientDataJSON(base64URLDecode(clientDataJSON), storedChallenge)) {
    return res.status(400).send("Invalid client data JSON");
  }

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
  if (verifyAuthenticatorDataAndAttestation(authenticatorData, registeredUsers[username].attestation, registeredUsers[username].clientData)) {
    return res.send(`User logged in successfully for ${username}`);
  } else {
    return res.status(401).send("Authentication failed.");
  }
});

const PORT = process.env.PORT || 3030;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
