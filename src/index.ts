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
} from "./helper";

const app = express();
app.use(express.json());

// Enable CORS for all routes
app.use(cors());

const registeredUsers: Record<
  string,
  { attestation?: string; clientData?: string; challenge?: string; challengeId?: string; credID: string; COSEPublicKey: any }
> = {
  //   "12": {
  //     attestation:
  //       "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFJ3jImqEXLFLrkNRfrOncBR9P3OopQECAyYgASFYIEJP95sicsTsvFh0Fxfql2DjoTD5z1GKDGCdTIEJS+piIlggqLIX3pbhZlOhcYhVI4EXb1E2tl0guLS/UTuRaytKCdo=",
  //     clientData:
  //       "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZFQzODU3X3giLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
  //   },
};

const challengeStorage = new Map();

app.post("/generate-challenge", (req, res) => {
  const { username, type } = req.body;
  const challenge = crypto.randomBytes(32).toString("base64");
  const challengeId = crypto.randomBytes(16).toString("hex");
  if (type === "register") {
    if (!registeredUsers[username]) {
      challengeStorage.set(challengeId, challenge);
      return res.json({ challengeId, challenge, rpName: "WebAuthn demo", rpId: "localhost" });
    } else {
      return res.status(400).send("User already registered!");
    }
  }
  if (type === "login") {
    if (registeredUsers[username]) {
      challengeStorage.set(challengeId, challenge);
      return res.json({ challengeId, challenge, rpName: "WebAuthn demo", rpId: "localhost" });
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
  console.log("==========registered: public key: " + COSEPublicKey);
  const userRegistrationData = { attestation: attestationObject, clientData: clientDataJSON, credID, COSEPublicKey }; // Store attestation object

  registeredUsers[username] = userRegistrationData;

  res.send(`User registered successfully with id ${username}`);
});

app.post("/login", (req, res) => {
  const { authenticatorData, username, clientDataJSON, challengeId, signature } = req.body;
  const storedChallenge = challengeStorage.get(challengeId);

  if (!storedChallenge) {
    return res.status(400).send("Invalid challenge ID");
  }

  // if (!verifyChallenge(base64URLDecode(clientDataJSON), storedChallenge)) {
  //   return res.status(400).send("Invalid client data JSON");
  // }

  //verify signature
  console.log("before signature verifying .........");
  // TODO: verify this function
  verifyLoginSignature(signature, authenticatorData, clientDataJSON, registeredUsers[username].COSEPublicKey);
  //   verifySignature(signature, authenticatorData, clientDataJSON, registeredUsers[username].COSEPublicKey);

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
