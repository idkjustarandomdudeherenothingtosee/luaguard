const crypto = require('crypto');
const { PastefyClient } = require('@interaapps/pastefy');

const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

// Generate random hash with embedded key
function generateHashWithKey(length = 136) {
    // Generate random bytes for the hash
    const hash = crypto.randomBytes(Math.ceil((length - 8) / 2))
        .toString('hex')
        .slice(0, length - 8);
    
    // Generate random 8-byte key
    const key = crypto.randomBytes(4).toString('hex'); // 8 chars hex = 4 bytes
    
    // Insert key at position 58 (0-indexed 57)
    const finalHash = hash.slice(0, 57) + key + hash.slice(57);
    
    return {
        fullHash: finalHash,
        key: key,
        hashWithoutKey: hash.slice(0, 57) + hash.slice(57) // Remove key
    };
}

// Extract key from hash (for decryption)
function extractKeyFromHash(fullHash) {
    return fullHash.substring(57, 65); // 8 chars from position 58
}

// Remove key from hash (for verification)
function removeKeyFromHash(fullHash) {
    return fullHash.substring(0, 57) + fullHash.substring(65);
}

// AES-256 encryption
function aesEncrypt(data, key) {
    // Convert hex key to buffer (8 chars hex = 4 bytes, need 32 bytes for AES-256)
    // We'll derive a proper 32-byte key from the 8-char key
    const keyBuffer = crypto.createHash('sha256').update(key).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    return {
        encrypted: encrypted,
        iv: iv.toString('base64')
    };
}

// Main encryption function
function encryptCode(code) {
    console.log('Starting encryption...');
    
    // Generate hash with embedded key
    const { fullHash, key, hashWithoutKey } = generateHashWithKey();
    console.log('✓ Generated 136-char hash with 8-char key at position 58');
    
    // Prepare data with hash for verification
    const dataToEncrypt = JSON.stringify({
        hash: hashWithoutKey, // Store hash without key for verification
        content: code
    });
    
    // AES encrypt with the key
    const aesResult = aesEncrypt(dataToEncrypt, key);
    console.log('✓ AES-256 encryption complete');
    
    return {
        fullHash: fullHash,     // 136 chars with key embedded
        encrypted: aesResult.encrypted,
        iv: aesResult.iv
    };
}

// Generate Lua format
function generateLuaFormat(fullHash, encrypted, iv) {
    return `getgenv().HASH_LG = "${fullHash}"
getgenv().CODE_LG = "${encrypted}"
getgenv().IV_LG = "${iv}"`;
}

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { code } = req.body;

        if (!code) {
            return res.status(400).json({ error: 'Code is required' });
        }

        console.log('Encrypting code...');
        
        // Encrypt the code
        const result = encryptCode(code);
        
        // Generate Lua format
        const luaContent = generateLuaFormat(
            result.fullHash,
            result.encrypted,
            result.iv
        );
        
        // Upload to Pastefy
        const client = new PastefyClient(PASTEFY_API_KEY);
        const paste = await client.createPaste({
            title: `🔒 LuaGuard - ${new Date().toLocaleString()}`,
            content: luaContent,
            visibility: 'UNLISTED',
            tags: ['luaguard', 'encrypted', 'aes-256']
        });

        return res.status(200).json({
            success: true,
            message: 'Code encrypted with AES-256',
            pasteUrl: `https://pastefy.app/${paste.id}`,
            pasteId: paste.id,
            hash: result.fullHash.substring(0, 20) + '...',
            keyPosition: 58,
            note: 'Key is at position 58-65 in the hash'
        });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({
            error: 'Encryption failed',
            details: error.message
        });
    }
};
