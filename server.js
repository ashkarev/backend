import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { PublicClientApplication } from "@azure/msal-node";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";

dotenv.config();

const app = express();
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'https://entra-orcin.vercel.app'
  ],
  credentials: true
}));
app.use(express.json());

// =====================================
// MSAL CONFIGURATION (for Device Code)
// =====================================

const msalConfig = {
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.TENANT_ID || 'common'}`,
  }
};

const pca = new PublicClientApplication(msalConfig);

// In-memory store for device code flows (still needed for polling, but short-lived)
const deviceFlows = new Map();

// =====================================
// TOKEN VALIDATION MIDDLEWARE
// =====================================

const client = jwksClient({
  jwksUri: `https://login.microsoftonline.com/common/discovery/v2.0/keys`
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    var signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

const validateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, getKey, {
    audience: process.env.CLIENT_ID,
    issuer: `https://login.microsoftonline.com/${process.env.TENANT_ID}/v2.0`
  }, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token", details: err.message });
    req.user = decoded;
    next();
  });
};

// =====================================
// ENDPOINTS
// =====================================

// Device Code Flow Start
app.post("/auth/device-code/start", async (req, res) => {
  const flowId = Date.now().toString();

  try {
    const deviceCodeRequest = {
      scopes: ["User.Read"],
      deviceCodeCallback: (response) => {
        deviceFlows.set(flowId, {
          status: "pending",
          userCode: response.userCode,
          verificationUri: response.verificationUri,
          message: response.message,
        });
      },
    };

    // Background promise for token acquisition
    pca.acquireTokenByDeviceCode(deviceCodeRequest)
      .then((response) => {
        deviceFlows.set(flowId, {
          status: "success",
          account: {
            username: response.account.username,
            name: response.account.name,
          }
        });
      })
      .catch((err) => {
        deviceFlows.set(flowId, { status: "failed", error: err.message });
      });

    // Wait briefly for callback to fire
    await new Promise(resolve => setTimeout(resolve, 500));

    const flow = deviceFlows.get(flowId);
    res.json({ flowId, ...flow });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Device Code Status Polling
app.get("/auth/device-code/status/:flowId", (req, res) => {
  const flow = deviceFlows.get(req.params.flowId);
  if (!flow) return res.status(404).json({ error: "Flow not found" });
  res.json(flow);
});

// Protected Profile Endpoint (Example)
app.get("/api/profile", validateToken, (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
