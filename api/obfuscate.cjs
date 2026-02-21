// api/obfuscate.cjs
const crypto = require('crypto');
const { PastefyClient } = require('@interaapps/pastefy');
const FormData = require('form-data');
const { Readable } = require('stream');

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

async function obfuscateWithWynfuscate(code) {
    const form = new FormData();
    
    // Create a stream from the code string
    const stream = Readable.from([code]);
    
    // Append as file
    form.append('file', stream, {
        filename: 'script.lua',
        contentType: 'text/plain',
    });
    
    form.append('targetPlatform', 'ROBLOX_COMPAT');
    form.append('enhancedCompression', 'true');

    // Get headers
    const headers = form.getHeaders();

    // Submit job
    const submitResponse = await fetch(`${WYNFUSCATE_URL}/obfuscate`, {
        method: 'POST',
        headers: { 
            'Authorization': `Bearer ${WYNFUSCATE_API_KEY}`,
            ...headers
        },
        body: form,
    });

    if (!submitResponse.ok) {
        const error = await submitResponse.text();
        console.error('Wynfuscate error:', error);
        throw new Error(`Wynfuscate submission failed: ${error}`);
    }

    const job = await submitResponse.json();
    console.log('Job submitted:', job.id);

    // Poll for completion
    let jobStatus;
    for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 2000));
        
        const statusResponse = await fetch(`${WYNFUSCATE_URL}/jobs/${job.id}`, {
            headers: { 'Authorization': `Bearer ${WYNFUSCATE_API_KEY}` }
        });
        
        if (!statusResponse.ok) continue;
        
        jobStatus = await statusResponse.json();
        
        if (jobStatus.status === 'completed') break;
        if (jobStatus.status === 'failed') throw new Error('Obfuscation failed');
    }

    // Download result
    const downloadResponse = await fetch(`${WYNFUSCATE_URL}/jobs/${job.id}/download`, {
        headers: { 'Authorization': `Bearer ${WYNFUSCATE_API_KEY}` }
    });
    
    if (!downloadResponse.ok) {
        throw new Error('Failed to download result');
    }
    
    return await downloadResponse.text();
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

        console.log('Obfuscating code...');
        
        // Step 1: Obfuscate with Wynfuscate
        const obfuscatedCode = await obfuscateWithWynfuscate(code);
        
        console.log('Obfuscation complete, encrypting...');

        // Step 2: Generate hash and encrypt
        const { fullHash, key, hashWithoutKey } = generateHashWithKey();
        
        const dataToEncrypt = JSON.stringify({
            hash: hashWithoutKey,
            content: obfuscatedCode
        });
        
        const encrypted = xorEncrypt(dataToEncrypt, key);
        
        // Step 3: Create paste on Pastefy
        const client = new PastefyClient(PASTEFY_API_KEY);
        const luaContent = `getgenv().HASH_LG = "${fullHash}"
getgenv().CODE_LG = "${encrypted}"`;

        const paste = await client.createPaste({
            title: `🔒 LuaGuard - ${new Date().toLocaleString()}`,
            content: luaContent,
            visibility: 'UNLISTED',
            tags: ['luaguard', 'xor']
        });

        console.log('Paste created:', paste.id);

        res.status(200).json({
            success: true,
            pasteUrl: `https://pastefy.app/${paste.id}`,
            pasteId: paste.id
        });

    } catch (error) {
        console.error('Obfuscation error:', error);
        res.status(500).json({ 
            success: false,
            error: error.message || 'Internal server error' 
        });
    }
};
