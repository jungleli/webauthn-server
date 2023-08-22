import express from "express";
import cors from "cors";
import crypto from "crypto";
import {
  base64URLDecode,
  verifyAuthenticatorDataAndAttestation,
  verifyClientDataJSON,
  verifyChallenge,
  parseAttestationObject,
  verifySignature,
  verifyLoginSignature,
  verifyRegistration,
  generateRegistrationOptions,
  generateLoginOptions,
} from "./helper";

const app = express();
app.use(express.json());

// Enable CORS for all routes
app.use(cors());

const registeredUsers: Record<
  string,
  { attestation?: string; clientData?: string; challenge?: string; challengeId?: string; credID: string; COSEPublicKey: any }
> = {};

const challengeStorage = new Map();

app.get("/generate-options", (req, res) => {
  const { username, type } = req.query as { username: string; type: string };
  const challenge = crypto.randomBytes(32).toString("base64");
  const userId = crypto.randomBytes(32).toString("base64");
  const challengeId = crypto.randomBytes(16).toString("hex");
  if (type === "register") {
    if (!registeredUsers[username]) {
      challengeStorage.set(challengeId, challenge);
      const publicKeyOptions = generateRegistrationOptions({ username, challenge, userId });
      return res.json({ publicKeyOptions, challengeId });
    } else {
      return res.status(400).send("User already registered!");
    }
  }
  if (type === "login") {
    if (registeredUsers[username]) {
      challengeStorage.set(challengeId, challenge);
      const publicKeyOptions = generateLoginOptions({ challenge });
      return res.json({ publicKeyOptions, challengeId });
    } else {
      return res.status(400).send("User not registered!");
    }
  }
});

app.post("/register", (req, res) => {
  const {
    authData: { attestationObject, clientDataJSON },
    username,
    challengeId,
  } = req.body;
  const storedChallenge = challengeStorage.get(challengeId);

  if (!storedChallenge) {
    return res.status(400).send("Invalid challenge ID");
  }

  if (!verifyChallenge(base64URLDecode(clientDataJSON), storedChallenge)) {
    return res.status(400).send("Invalid client data JSON");
  }

  const { credID, COSEPublicKey } = parseAttestationObject(base64URLDecode(attestationObject));
  const userRegistrationData = { attestation: attestationObject, clientData: clientDataJSON, credID, COSEPublicKey }; // Store attestation object

  registeredUsers[username] = userRegistrationData;

  res.send(`User registered successfully with id ${username}`);
});

app.post("/login", async (req, res) => {
  const { authenticatorData, username, clientDataJSON, signature, challengeId } = req.body;
  const storedChallenge = challengeStorage.get(challengeId);

  if (!storedChallenge) {
    return res.status(400).send("Invalid challenge ID");
  }

  // if (!verifyChallenge(base64URLDecode(clientDataJSON), storedChallenge)) {
  //   return res.status(400).send("Invalid client data JSON");
  // }

  const verified = await verifyLoginSignature(signature, authenticatorData, clientDataJSON, registeredUsers[username].COSEPublicKey);
  if (verified) {
    return res.send(`User logged in successfully for ${username}`);
  } else {
    return res.status(401).send("Authentication failed.");
  }
  //   verifySignature(signature, authenticatorData, clientDataJSON, registeredUsers[username].COSEPublicKey);

  // Simulate a login process by comparing authenticator data
  //   if (verifyAuthenticatorDataAndAttestation(authenticatorData, registeredUsers[username].attestation, registeredUsers[username].clientData)) {
  //     return res.send(`User logged in successfully for ${username}`);
  //   } else {
  //     return res.status(401).send("Authentication failed.");
  //   }
});

const PORT = process.env.PORT || 3030;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
