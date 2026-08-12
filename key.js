// generate-keys.js
// Run with: node generate-keys.js
// Creates private.pem and public.pem in the current folder.

// const crypto = require("crypto");
// const fs = require("fs");

// const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
//   modulusLength: 2048,
//   publicKeyEncoding: { type: "spki", format: "pem" },
//   privateKeyEncoding: { type: "pkcs8", format: "pem" },
// });

// fs.writeFileSync("private.pem", privateKey);
// fs.writeFileSync("public.pem", publicKey);

// console.log("Created private.pem and public.pem in this folder.");
// console.log("private.pem -> paste into WHATSAPP_FLOW_PRIVATE_KEY (keep secret!)");
// console.log("public.pem  -> upload to Meta");

// upload-public-key.js
// Run with: node upload-public-key.js
// Requires Node 18+ (built-in fetch, FormData, Blob).

const fs = require("fs");

const PHONE_NUMBER_ID = "792328513955165"; // from Meta App Dashboard > WhatsApp > API Setup
const ACCESS_TOKEN = "EAARV53drZAMIBRseMZCgCorswKhvwvp0UI8VcJdM9sZA0zOaW4ZAYlttAHIktflKL9biN1ereXCKC9pHwLMc3NasgcIjhiw5RqJn4uHZBsty4ATw0rvvlkoMOdICofkhGSlB5MP8R3OmE01EToBUzUrIZBvW061eFK47O5AtfsLShfCTJ6cmr79ALZCvH4UxpMttgZDZD"; // same place

async function uploadPublicKey() {
    const publicKeyContent = fs.readFileSync("public.pem", "utf-8");
   
    const form = new FormData();
    form.append("business_public_key", publicKeyContent);
   
    const response = await fetch(
      `https://graph.facebook.com/v21.0/${PHONE_NUMBER_ID}/whatsapp_business_encryption`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${ACCESS_TOKEN}`,
        },
        body: form,
      }
    );
   
    const result = await response.json();
   
    if (!response.ok) {
      console.error("Upload failed:", result);
      return;
    }
   
    console.log("Public key uploaded successfully:", result);
  }
   
  uploadPublicKey();