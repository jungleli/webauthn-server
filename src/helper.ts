import crypto from "crypto";

function generateRandomUserId() {
  return crypto.randomBytes(8).toString("hex");
}
export { generateRandomUserId };
