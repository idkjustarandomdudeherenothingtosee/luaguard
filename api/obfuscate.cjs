// api/obfuscate.cjs
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { PastefyClient } = require('@interaapps/pastefy');
const FormData = require('form-data');
const axios = require('axios');

const WYNFUSCATE_API_KEY = 'wynf_ew84z6L93odfnAc017sZaJdOVTwPBvH0';
const WYNFUSCATE_URL = 'https://wynfuscate.com/api/v1';
const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

function generateHashWithKey() {
    const hash = crypto.randomBytes(64).toString('hex');
    const key = crypto.randomBytes(4).toString('hex');
    const finalHash = hash.slice(0, 57) + key + hash.slice(57);
    return {
        fullHash: finalHash,
        key: key,
        hashWithoutKey: hash
    };
}

function xorEncrypt(data, key) {
    let result = "";
    for (let i = 0; i < data.length; i++) {
        const keyChar = key.charCodeAt(i % key.length);
        const dataChar = data.charCodeAt(i);
        result += String.fromCharCode(dataChar ^ keyChar);
    }
    return Buffer.from(result).toString('base64');
}

function addLoaderCode(fullHash, encrypted) {
    return `getgenv().HASH_LG = "${fullHash}"
getgenv().CODE_LG = "${encrypted}"

if not isfile("LUAGUARD/init.lua") then
    writefile("LUAGUARD/init.lua", game:HttpGet("https://raw.githubusercontent.com/idkjustarandomdudeherenothingtosee/luaguard/refs/heads/main/sdk/init.lua"))
    loadstring(readfile("LUAGUARD/init.lua"))()
else
    loadstring(readfile("LUAGUARD/init.lua"))()
end`;
}

async function obfuscateWithWynfuscate(code) {
    // Create temp file
    const tempDir = os.tmpdir();
    const tempFilePath = path.join(tempDir, `script_${Date.now()}.lua`);
    
    try {
        // Write code to temp file
        fs.writeFileSync(tempFilePath, code, 'utf-8');
        
        // Create form data exactly like the working example
        const form = new FormData();
        form.append('file', fs.createReadStream(tempFilePath), {
            filename: 'script.lua',
            contentType: 'text/plain'
        });
        form.append('targetPlatform', 'ROBLOX_COMPAT');
        form.append('enhancedCompression', 'true');

        // Get form headers
        const formHeaders = form.getHeaders();

        console.log('Submitting to Wynfuscate...');

        // Submit job using axios (like the working example)
        const submitResponse = await axios.post(`${WYNFUSCATE_URL}/obfuscate`, form, {
            headers: {
                ...formHeaders,
                'Authorization': `Bearer ${WYNFUSCATE_API_KEY}`
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity
        });

        const job = submitResponse.data;
        console.log('Job submitted:', job.id);

        // Poll for completion with exponential backoff
        let pollInterval = 2000;
        const maxInterval = 30000;
        const maxPolls = 60;

        for (let polls = 0; polls < maxPolls; polls++) {
            const statusResponse = await axios.get(`${WYNFUSCATE_URL}/jobs/${job.id}`, {
                headers: { 'Authorization': `Bearer ${WYNFUSCATE_API_KEY}` }
            });
            
            const status = statusResponse.data;

            if (status.status === 'completed') {
                console.log(`Processing complete! (${status.processingTimeMs}ms)`);
                break;
            } else if (status.status === 'failed') {
                throw new Error(`Job failed: ${status.error?.message || 'Unknown error'}`);
            }

            await new Promise(r => setTimeout(r, pollInterval));
            pollInterval = Math.min(pollInterval * 1.5, maxInterval);
        }

        // Download result
        console.log('Downloading obfuscated file...');
        
        const downloadResponse = await axios.get(`${WYNFUSCATE_URL}/jobs/${job.id}/download`, {
            headers: { 'Authorization': `Bearer ${WYNFUSCATE_API_KEY}` },
            responseType: 'arraybuffer'
        });

        return Buffer.from(downloadResponse.data).toString('utf-8');

    } finally {
        // Clean up temp file
        try {
            fs.unlinkSync(tempFilePath);
        } catch (e) {
            console.error('Failed to delete temp file:', e);
        }
    }
}

module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    // Only allow POST
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { code } = req.body;
        
        if (!code) {
            return res.status(400).json({ error: 'Code is required' });
        }

        if (typeof code !== 'string') {
            return res.status(400).json({ error: 'Code must be a string' });
        }

        console.log('Starting Wynfuscate obfuscation with temp file...');
        
        // Step 1: Obfuscate with Wynfuscate
        const obfuscatedCode = await obfuscateWithWynfuscate(code);
        
        console.log('Wynfuscate success, creating paste...');

        // Step 2: Generate hash and encrypt
        const { fullHash, key, hashWithoutKey } = generateHashWithKey();
        
        const dataToEncrypt = JSON.stringify({
            hash: hashWithoutKey,
            content: obfuscatedCode
        });
        
        const encrypted = xorEncrypt(dataToEncrypt, key);
        
        // Step 3: Create paste on Pastefy with loader code
        const client = new PastefyClient(PASTEFY_API_KEY);
        const finalContent = addLoaderCode(fullHash, encrypted);

        const paste = await client.createPaste({
            title: `🔒 LuaGuard - ${new Date().toLocaleString()}`,
            content: finalContent,
            visibility: 'UNLISTED',
            tags: ['luaguard', 'xor', 'loader']
        });

        console.log('Paste created:', paste.id);

        res.status(200).json({
            success: true,
            pasteUrl: `https://pastefy.app/${paste.id}`
        });

    } catch (error) {
        console.error('Error:', error);
        
        // Better error response
        if (error.response) {
            // Axios error with response
            res.status(500).json({ 
                error: `API Error: ${error.response.status} - ${JSON.stringify(error.response.data)}` 
            });
        } else {
            res.status(500).json({ error: error.message });
        }
    }
};
