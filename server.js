import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { PublicClientApplication } from "@azure/msal-node";

dotenv.config();

const app = express();
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'https://entra-gjvt.vercel.app'
  ],
  credentials: true
}));
app.use(express.json());

// MSAL Configuration - Dynamic authority
const config = {
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: process.env.TENANT_ID 
      ? `https://login.microsoftonline.com/${process.env.TENANT_ID}`
      : "https://login.microsoftonline.com/common",
  },
};

const pca = new PublicClientApplication(config);

// In-memory storage for device code flows
const deviceFlows = new Map();

// =====================================
// DEVICE CODE FLOW - FIXED RACE CONDITION
// =====================================

app.post("/auth/device-code/start", async (req, res) => {
  const flowId = Date.now().toString();

  try {
    // Promise that resolves when callback fires
    const waitForCallback = new Promise((resolve, reject) => {
      const deviceCodeRequest = {
        scopes: ["User.Read", "offline_access"],
        deviceCodeCallback: (response) => {
          deviceFlows.set(flowId, {
            status: "pending",
            userCode: response.userCode,
            deviceCode: response.deviceCode,
            verificationUri: response.verificationUri,
            message: response.message,
            expiresIn: response.expiresIn,
          });
          console.log(`[Device Code Flow ${flowId}] User code: ${response.userCode}`);
          resolve(); // Callback fired successfully
        },
      };

      // Start the flow
      pca.acquireTokenByDeviceCode(deviceCodeRequest)
        .then((tokenResponse) => {
          deviceFlows.set(flowId, {
            status: "success",
            accessToken: tokenResponse.accessToken,
            account: tokenResponse.account,
            expiresOn: tokenResponse.expiresOn,
          });
          console.log(`[Device Code Flow ${flowId}] ✅ Authentication successful`);
        })
        .catch((error) => {
          deviceFlows.set(flowId, {
            status: "failed",
            error: error.message,
          });
          console.error(`[Device Code Flow ${flowId}] ❌ Authentication failed:`, error.message);
        });
    });

    // Wait for callback to fire
    await waitForCallback;

    // Get flow info and send to frontend
    const flowInfo = deviceFlows.get(flowId);
    if (!flowInfo) {
      return res.status(500).json({ error: "Failed to initiate device code flow" });
    }

    res.json({
      flowId,
      userCode: flowInfo.userCode,
      verificationUri: flowInfo.verificationUri,
      message: flowInfo.message,
      expiresIn: flowInfo.expiresIn,
    });

  } catch (error) {
    console.error("Device code flow error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Poll for device code flow status
app.get("/auth/device-code/status/:flowId", (req, res) => {
  const { flowId } = req.params;
  const flow = deviceFlows.get(flowId);

  if (!flow) {
    return res.status(404).json({ error: "Flow not found" });
  }

  if (flow.status === "success") {
    res.json({
      status: "success",
      account: {
        username: flow.account.username,
        name: flow.account.name,
      },
      expiresOn: flow.expiresOn,
    });
  } else if (flow.status === "failed") {
    res.json({
      status: "failed",
      error: flow.error,
    });
  } else {
    res.json({
      status: "pending",
      userCode: flow.userCode,
      verificationUri: flow.verificationUri,
    });
  }
});

// =====================================
// PRIMARY REFRESH TOKEN (PRT) INFO
// =====================================

app.get("/auth/prt/info", (req, res) => {
  res.json({
    name: "Primary Refresh Token (PRT)",
    description: "PRT is a special JWT token used by Windows 10/11 for SSO across apps and services.",
    requirements: [
      "Windows 10/11 device joined to Azure AD",
      "Windows Hello or device registration",
      "Enterprise environment with Conditional Access policies",
    ],
    note: "True PRT flow requires device-level registration and cannot be fully demonstrated in a web app. This endpoint provides information about PRT concepts.",
    referenceFlow: {
      step1: "User authenticates with Windows Hello/PIN on Azure AD-joined device",
      step2: "Device obtains PRT from Azure AD",
      step3: "Apps use PRT to silently acquire access tokens without re-authentication",
      step4: "PRT is bound to device TPM for security",
    },
    simulatedBehavior: "In this demo, we show the concept through device code flow, which shares similar silent authentication principles.",
  });
});

// Simulate PRT-like silent token acquisition
app.post("/auth/prt/silent-token", async (req, res) => {
  try {
    const accounts = await pca.getTokenCache().getAllAccounts();
    
    if (accounts.length === 0) {
      return res.status(401).json({
        error: "No cached accounts found",
        message: "In real PRT flow, the device would have a cached PRT. Please authenticate first using device code flow.",
      });
    }

    const silentRequest = {
      account: accounts[0],
      scopes: ["User.Read"],
    };

    const tokenResponse = await pca.acquireTokenSilent(silentRequest);

    res.json({
      status: "success",
      message: "Token acquired silently (simulating PRT behavior)",
      account: {
        username: tokenResponse.account.username,
        name: tokenResponse.account.name,
      },
      expiresOn: tokenResponse.expiresOn,
    });
  } catch (error) {
    res.status(401).json({
      error: "Silent authentication failed",
      message: error.message,
      note: "This simulates PRT token refresh failure. User would need to re-authenticate.",
    });
  }
});

// =====================================
// UTILITY ENDPOINTS
// =====================================

app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.get("/auth/accounts", async (req, res) => {
  try {
    const accounts = await pca.getTokenCache().getAllAccounts();
    res.json({
      count: accounts.length,
      accounts: accounts.map((acc) => ({
        username: acc.username,
        name: acc.name,
        environment: acc.environment,
      })),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/auth/logout", async (req, res) => {
  try {
    const accounts = await pca.getTokenCache().getAllAccounts();
    for (const account of accounts) {
      await pca.getTokenCache().removeAccount(account);
    }
    deviceFlows.clear();
    res.json({ message: "All accounts logged out", count: accounts.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =====================================
// START SERVER - Bind to 127.0.0.1
// =====================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`
🚀 Entra ID Authentication Server
================================
Server running on: http://127.0.0.1:${PORT}

Available Endpoints:
- POST /auth/device-code/start
- GET  /auth/device-code/status/:flowId
- GET  /auth/prt/info
- POST /auth/prt/silent-token
- GET  /auth/accounts
- POST /auth/logout
- GET  /health
  `);
});