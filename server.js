import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { PublicClientApplication, CryptoProvider } from "@azure/msal-node";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import fs from "fs";
import path from "path";

dotenv.config();

const app = express();

// =====================================
// CORS CONFIGURATION
// =====================================
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://entra-orcin.vercel.app',
  /\.vercel\.app$/ // Allow all Vercel previews
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.some(pattern => 
      typeof pattern === 'string' ? pattern === origin : pattern.test(origin)
    )) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(express.json());

// =====================================
// MSAL PERSISTENT CACHE
// =====================================
// On Render/Vercel, file persistence might be ephemeral. 
// For "Real" production, swap this with Redis or MongoDB.
const CACHE_PATH = path.resolve("./msal_cache.json");

const beforeCacheAccess = async (cacheContext) => {
    try {
        if (fs.existsSync(CACHE_PATH)) {
            cacheContext.tokenCache.deserialize(fs.readFileSync(CACHE_PATH, "utf-8"));
        }
    } catch (err) {
        console.error("Cache Read Error:", err);
    }
};

const afterCacheAccess = async (cacheContext) => {
    if (cacheContext.cacheHasChanged) {
        try {
            fs.writeFileSync(CACHE_PATH, cacheContext.tokenCache.serialize());
        } catch (err) {
            console.error("Cache Write Error:", err);
        }
    }
};

const cachePlugin = {
    beforeCacheAccess,
    afterCacheAccess
};

// =====================================
// MSAL CONFIGURATION
// =====================================
const msalConfig = {
  auth: {
    clientId: process.env.CLIENT_ID || process.env.VITE_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${process.env.TENANT_ID || 'common'}`,
  },
  cache: {
    cachePlugin
  }
};

const pca = new PublicClientApplication(msalConfig);
const deviceFlows = new Map();

// =====================================
// TOKEN VALIDATION
// =====================================
const client = jwksClient({
  jwksUri: `https://login.microsoftonline.com/common/discovery/v2.0/keys`
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    if (err) return callback(err);
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

const validateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, getKey, {
    audience: process.env.CLIENT_ID || process.env.VITE_CLIENT_ID,
    issuer: [
        `https://login.microsoftonline.com/${process.env.TENANT_ID}/v2.0`,
        `https://sts.windows.net/${process.env.TENANT_ID}/`
    ]
  }, (err, decoded) => {
    if (err) {
        console.error("Token Validation Failed:", err.message);
        return res.status(401).json({ error: "Invalid token", details: err.message });
    }
    req.user = decoded;
    next();
  });
};

// =====================================
// ENDPOINTS
// =====================================

app.post("/auth/device-code/start", async (req, res) => {
  const flowId = Date.now().toString();
  console.log(`Starting device code flow: ${flowId}`);

  try {
    const deviceCodeRequest = {
      scopes: ["User.Read", "offline_access"],
      deviceCodeCallback: (response) => {
        console.log("Device code generated:", response.userCode);
        deviceFlows.set(flowId, {
          status: "pending",
          userCode: response.userCode,
          verificationUri: response.verificationUri,
          message: response.message,
        });
      },
    };

    pca.acquireTokenByDeviceCode(deviceCodeRequest)
      .then((response) => {
        console.log("Device flow success for:", response.account.username);
        deviceFlows.set(flowId, {
          status: "success",
          account: {
            username: response.account.username,
            name: response.account.name,
          }
        });
      })
      .catch((err) => {
        console.error("Device flow error:", err.message);
        deviceFlows.set(flowId, { status: "failed", error: err.message });
      });

    let attempts = 0;
    while (!deviceFlows.has(flowId) && attempts < 10) {
        await new Promise(r => setTimeout(r, 100));
        attempts++;
    }

    const flow = deviceFlows.get(flowId);
    res.json({ flowId, ...flow });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/auth/device-code/status/:flowId", (req, res) => {
  const flow = deviceFlows.get(req.params.flowId);
  if (!flow) return res.status(404).json({ error: "Flow not found" });
  res.json(flow);
});

app.get("/api/profile", validateToken, (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

app.get("/health", (req, res) => res.json({ 
    status: "ok", 
    env: {
        clientId: process.env.CLIENT_ID ? "Set" : "Missing",
        tenantId: process.env.TENANT_ID || "common"
    }
}));

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend Fixed & Running on port ${PORT}`);
});
