import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { supabaseAdmin } from "@/lib/automations/admin-client";
import { decrypt } from "@/lib/whatsapp/encryption";
import { isValidE164 } from "@/lib/whatsapp/phone-utils";

// Meta requires this route to be dynamically executed (not statically cached)
export const dynamic = "force-dynamic";

const APP_SECRET = process.env.META_APP_SECRET as string;
const PRIVATE_KEY = process.env.WHATSAPP_FLOW_PRIVATE_KEY as string;
const PASSPHRASE = process.env.WHATSAPP_FLOW_PRIVATE_KEY_PASSPHRASE || undefined;


// ---------------------------------------------------------------------------
// Decrypt an incoming Flow request
// ---------------------------------------------------------------------------
function decryptRequest(
  body: { encrypted_aes_key: string; encrypted_flow_data: string; initial_vector: string },
  privatePem: string,
  passphrase?: string
) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: crypto.createPrivateKey({ key: privatePem, format: "pem", passphrase }),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encrypted_aes_key, "base64")
  );

  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const initialVectorBuffer = Buffer.from(initial_vector, "base64");

  const TAG_LENGTH = 16;
  const encryptedBody = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const encryptedTag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv("aes-128-gcm", decryptedAesKey, initialVectorBuffer);
  decipher.setAuthTag(encryptedTag);

  const decryptedJSONString = Buffer.concat([
    decipher.update(encryptedBody),
    decipher.final(),
  ]).toString("utf-8");

  return {
    decryptedBody: JSON.parse(decryptedJSONString),
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer,
  };
}

// ---------------------------------------------------------------------------
// Encrypt the response back to the Flow (IV bits are flipped per spec)
// ---------------------------------------------------------------------------
function encryptResponse(response: unknown, aesKeyBuffer: Buffer, initialVectorBuffer: Buffer) {
  const flippedIv = Buffer.from([...initialVectorBuffer].map((b) => b ^ 0xff));

  const cipher = crypto.createCipheriv("aes-128-gcm", aesKeyBuffer, flippedIv);

  return Buffer.concat([
    cipher.update(JSON.stringify(response), "utf-8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
}

function isRequestSignatureValid(
    rawBody: string,
    signatureHeader: string | null,
): boolean {
    if(!APP_SECRET) {
      console.warn("App Secret is not set up. Please Add your app secret in /.env file to check for request validation");
      return true;
    }
    if (!signatureHeader) return false;
  
    const signatureBuffer = Buffer.from(signatureHeader.replace("sha256=", ""), "utf-8");
  
    const hmac = crypto.createHmac("sha256", APP_SECRET);
    const digestString = hmac.update(rawBody).digest('hex');
    const digestBuffer = Buffer.from(digestString, "utf-8");
  
    if ( !crypto.timingSafeEqual(digestBuffer, signatureBuffer)) {
      console.error("Error: Request Signature did not match");
      return false;
    }
    return true;
  }
// ---------------------------------------------------------------------------
// POST /api/whatsapp-flow
// Configure this URL in WhatsApp Manager > your Flow > Edit Flow > Endpoint,
// e.g. https://yourdomain.com/api/whatsapp-flow
// ---------------------------------------------------------------------------
export async function POST(req: NextRequest) {
  const rawBody = await req.text();

  // const signatureHeader = req.headers.get("x-hub-signature-256");
  // if (!isRequestSignatureValid(rawBody, signatureHeader)) {
  //   console.log(rawBody, signatureHeader);
    
  //   return new NextResponse("Invalid signature", { status: 432 });
  // }

  const body = JSON.parse(rawBody);
  // const phoneNumberId = body?.entry?.[0]?.changes?.[0]?.value?.metadata?.phone_number_id;
// return console.log(body);

  let decrypted;
  try {
    decrypted = decryptRequest(body, PRIVATE_KEY, PASSPHRASE);
  } catch (err) {
    console.error("Decryption failed:", err);
    // 421 tells the client to re-fetch the public key and retry
    return new NextResponse(null, { status: 421 });
  }

  const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decrypted;
  const { action, screen, data, flow_token } = decryptedBody;
  // console.log("Decrypted Flow request:", decryptedBody);


  const encrypt = (payload: unknown) =>
    new NextResponse(encryptResponse(payload, aesKeyBuffer, initialVectorBuffer), {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });

  try {
    // Health check ping — WhatsApp calls this periodically
    if (action === "ping") {
      return encrypt({ data: { status: "active" } });
    }

    // Client reporting our previous response was invalid
    if (data?.error) {
      console.error("Flow client error notification:", data);
      return encrypt({ data: { acknowledged: true } });
    }

    // Flow just opened
    if (action === "INIT") {
      return encrypt({
        screen: "CONTACT", // match your Flow JSON's first screen name
        data: {},
      });
    }

    // A screen was submitted
    if (action === "data_exchange") {
      // DEBUG: log every step so we can see exactly what data arrives where
      // console.log(`[data_exchange] screen=${screen} received data:`, data);
 
      // ---- FINAL ANSWERS LAND HERE ----
      // `data` holds whatever fields the user filled in on that screen.
      // `screen` tells you which screen just submitted.
 
      // CONTACT -> PROFESSIONAL
      // Forward what was just submitted so PROFESSIONAL's ${data.x} bindings resolve
      if (screen === "CONTACT") {
        // console.log("[data_exchange] sending to PROFESSIONAL with data:", { ...data });
        return encrypt({ screen: "PROFESSIONAL", data: { ...data } });
      }
 
      // PROFESSIONAL -> GOALS
      // `data` here already includes full_name/email/phone (forwarded via ${data.x}
      // in the flow JSON) plus role/company just submitted — forward it all again
      if (screen === "PROFESSIONAL") {
        return encrypt({ screen: "GOALS", data: { ...data } });
      }
 
      const isFinalScreen = screen === "GOALS";
 
      if (isFinalScreen) {
        // This is the payload you asked for — the final submitted answers.
        const finalAnswers = { timestamp: new Date().toISOString(), flow_token, ...data };
 
        // You can also: save to a DB, call another API, send an email, etc.
        try{
          await saveRegistrationToSupabase(finalAnswers);
          const normalizedPhone = finalAnswers.phone?.replace(/[^\d]/g, "");
          await sendCtaUrlMessage({
            to: normalizedPhone,
            bodyText: `Hi ${finalAnswers.full_name}, Thank you for signing up for Automate & Elevate. We’ve sent the webinar access details to your WhatsApp/Emai.`,
            buttonText: "Join Group",
            url: "https://chat.whatsapp.com/FuQmU5UeZHQJoJ70IDxOv6", // your real group invite link
            phoneNumberId: "792328513955165"
          });
        }catch(err){
          console.log(err);
          
        }
 
        return encrypt({
          screen: "SUCCESS",
          data: {
            extension_message_response: {
              params: { flow_token },
            },
          },
        });
      }
      }

    // BACK button pressed (only received if refresh_on_back is true)
    if (action === "BACK") {
      return encrypt({ screen, data: {} });
    }

    return new NextResponse(null, { status: 400 });
  } catch (err) {
    console.error("Error handling Flow request:", err);
    return new NextResponse(null, { status: 500 });
  }
}

// Simple GET so you can sanity-check the route is deployed
export async function GET() {
  return NextResponse.json({ status: "WhatsApp Flow endpoint is running" });
}



export type WebinarRegistration = {
  timestamp: string;
  flow_token: string;
  full_name?: string;
  email?: string;
  phone?: string;
  role?: string;
  company?: string;
  goal?: string;
  questions?: string;
};
 
/**
 * Inserts one completed Flow submission into the `webinar_registrations` table.
 */
export async function saveRegistrationToSupabase(row: WebinarRegistration) {

  const supabase = supabaseAdmin()
  const { data, error } = await supabase
  .from("webinar_registrations")
  .insert([row])
    .select();
 
  if (error) {
    console.error("Supabase insert failed:", error);
    throw error;
  }
  
  // console.log("Saved to Supabase:", data);
  return data;
}


export async function sendCtaUrlMessage({
  to,
  bodyText,
  buttonText,
  url,
  headerText,
  phoneNumberId,
}: {
  to: string;
  bodyText: string;
  buttonText: string;
  url: string;
  headerText?: string;
  phoneNumberId?: string;
}) {
  console.log('send template');
  const supabase = supabaseAdmin()
 
  
  const { data: config, error: configError } = await supabase
    .from("whatsapp_config")
    .select("*")
    .eq("phone_number_id", phoneNumberId)
    .single();

    if (configError || !config) {
      console.log(`No WhatsApp config found for phone number ID: ${phoneNumberId}`);
      
      return NextResponse.json(
        {
          error:
            'WhatsApp not configured. Please set up your WhatsApp integration first.',
        },
        { status: 400 }
      )
    }

    const accessToken = decrypt(config.access_token)


  const sanitized = formatPhoneNumber(to)

      if (!isValidE164(sanitized)) {
        console.log(`Invalid phone number: ${sanitized}`);
        
        return NextResponse.json(
          { error: 'Invalid phone number.' },
          { status: 400 },
        )
      }

      const payload = {
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to:sanitized,
        type: "interactive",
        interactive: {
          type: "cta_url",
          header: { type: "text", text: "🎉 You’re registered!" },
          body: { text: bodyText },
          action: {
            name: "cta_url",
            parameters: {
              display_text: buttonText, // e.g. "Join Group" — keep it short
              url, // your WhatsApp group invite link, e.g. https://chat.whatsapp.com/xxxxxxx
            },
          },
        },
      };
     
      const response = await fetch(
        `https://graph.facebook.com/v21.0/${config.phone_number_id}/messages`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );
     
      const result = await response.json();
     
      if (!response.ok) {
        console.error("Failed to send CTA URL message:", result);
        throw new Error(result?.error?.message || "WhatsApp send failed");
      }
     
      console.log("CTA URL message sent:", result);
}


function formatPhoneNumber(input: any) {
  // Remove all non-digit characters
  let cleaned = input.replace(/\D/g, '');
  
  // If the number doesn't start with 91, add it
  if (!cleaned.startsWith('91')) {
      cleaned = '91' + cleaned;
  }
  
  // Basic validation: minimum length for Indian phone number (91 + 10 digits = 12 digits)
  if (cleaned.length < 12) {
      return 'Invalid phone number: too short';
  }
  
  // Optional: Check if it's a valid mobile number (starts with 6-9 after country code)
  // For Indian mobile numbers: 91 + 6/7/8/9 + 9 digits
  if (!/^91[6-9]\d{9}$/.test(cleaned)) {
      return 'Invalid phone number: not a valid Indian mobile number';
  }
  
  return cleaned;
}
