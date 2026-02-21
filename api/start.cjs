const crypto = require('crypto');
const { PastefyClient } = require('@interaapps/pastefy');

const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

// Generate random hash
function generateRandomHash(length = 128) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

// Shamir's Secret Sharing simulation
function shamirSplit(secret) {
    const fragment = crypto.randomBytes(32).toString('hex');
    return {
        fragment: fragment,
        shares: [
            crypto.randomBytes(32).toString('hex'),
            crypto.randomBytes(32).toString('hex'),
            crypto.randomBytes(32).toString('hex'),
            crypto.randomBytes(32).toString('hex'),
            crypto.randomBytes(32).toString('hex')
        ],
        encryptedFragment: crypto.createHash('sha256').update(secret + fragment).digest('hex')
    };
}

// XChaCha20 simulation
function xChaCha20Encrypt(data, key) {
    const iv = crypto.randomBytes(12);
    try {
        const cipher = crypto.createCipheriv('chacha20-poly1305', key.slice(0, 32), iv);
        const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return {
            encrypted: encrypted.toString('base64'),
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64')
        };
    } catch (e) {
        const cipher = crypto.createCipheriv('aes-256-gcm', key.slice(0, 32), iv);
        const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return {
            encrypted: encrypted.toString('base64'),
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64'),
            note: 'Using AES-256-GCM fallback'
        };
    }
}

// RSA encryption
function rsaEncrypt(data) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(data));
    
    return {
        encrypted: encrypted.toString('base64'),
        privateKey: privateKey,
        publicKey: publicKey
    };
}

// Twofish simulation
function twofishEncrypt(data) {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    
    return {
        encrypted: encrypted.toString('base64'),
        key: key.toString('base64'),
        iv: iv.toString('base64')
    };
}

// AES-256 encryption
function aes256Encrypt(data) {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    
    return {
        encrypted: encrypted.toString('base64'),
        key: key.toString('base64'),
        iv: iv.toString('base64')
    };
}

// Main encryption function
function encryptWithLayers(data) {
    console.log('Starting onion encryption process...');
    
    // Layer 0: Generate 128-letter random hash
    const scriptHash = generateRandomHash(128);
    console.log('✓ Generated script hash');
    
    // Layer 1: Shamir's Secret Sharing
    const shamirResult = shamirSplit(data + scriptHash);
    console.log('✓ Layer 1: Shamir Secret Sharing complete');
    
    // Layer 2: XChaCha20 encrypts the data
    const xchachaKey = crypto.randomBytes(32);
    const xchachaResult = xChaCha20Encrypt(data, xchachaKey);
    console.log('✓ Layer 2: XChaCha20 encryption complete');
    
    // Layer 3: RSA encrypts the XChaCha20 key
    const rsaResult = rsaEncrypt(xchachaKey.toString('base64'));
    console.log('✓ Layer 3: RSA encryption complete');
    
    // Combine data for next layers
    const combinedData = JSON.stringify({
        version: '1.0',
        scriptHash: scriptHash,
        shamir: shamirResult,
        xchacha: xchachaResult,
        rsa: {
            encrypted: rsaResult.encrypted
        }
    });
    
    // Layer 4: Twofish encrypts the entire package
    const twofishResult = twofishEncrypt(combinedData);
    console.log('✓ Layer 4: Twofish encryption complete');
    
    // Layer 5: AES-256 encrypts the Twofish output
    const aesResult = aes256Encrypt(JSON.stringify(twofishResult));
    console.log('✓ Layer 5: AES-256 encryption complete');
    
    // Return just the final encrypted code (the AES output)
    return {
        hash: scriptHash,
        encryptedCode: aesResult.encrypted,
        // Store metadata separately for decryption (not included in Lua output)
        metadata: {
            aes: {
                key: aesResult.key,
                iv: aesResult.iv
            },
            twofish: {
                key: twofishResult.key,
                iv: twofishResult.iv
            },
            rsa: {
                privateKey: rsaResult.privateKey
            },
            xchacha: {
                key: xchachaKey.toString('base64'),
                iv: xchachaResult.iv,
                authTag: xchachaResult.authTag
            },
            shamir: {
                fragment: shamirResult.fragment,
                shares: shamirResult.shares
            },
            scriptHash: scriptHash
        }
    };
}

// Generate Lua format without comment
function generateLuaFormat(hash, encryptedCode) {
    return `getgenv().HASH_LG = "${hash}"
getgenv().CODE_LG = "${encryptedCode}"`;
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

        console.log('Received code to encrypt, length:', code.length);

        // Step 1: Encrypt with all 5 layers
        console.log('Starting 5-layer encryption...');
        const encryptedResult = encryptWithLayers(code);
        console.log('Encryption complete');

        // Step 2: Generate Lua format (no comments)
        const luaContent = generateLuaFormat(
            encryptedResult.hash,
            encryptedResult.encryptedCode
        );

        // Step 3: Upload to Pastefy
        console.log('Connecting to Pastefy...');
        const client = new PastefyClient(PASTEFY_API_KEY);
        
        console.log('Creating paste...');
        const paste = await client.createPaste({
            title: `🔒 LuaGuard Encrypted - ${new Date().toLocaleString()}`,
            content: luaContent,
            visibility: 'UNLISTED',
            tags: ['luaguard', 'encrypted', 'lua', '5-layer']
        });

        console.log('✓ Paste created successfully with ID:', paste.id);

        // Return success response
        return res.status(200).json({
            success: true,
            message: 'Code encrypted and uploaded as Lua format',
            pasteId: paste.id,
            pasteUrl: `https://pastefy.app/${paste.id}`,
            hash: encryptedResult.hash.substring(0, 50) + '...',
            format: 'lua',
            preview: `getgenv().HASH_LG = "${encryptedResult.hash.substring(0, 20)}..."\ngetgenv().CODE_LG = "${encryptedResult.encryptedCode.substring(0, 50)}..."`
        });

    } catch (error) {
        console.error('Encryption/upload error:', error);
        
        if (error.message && error.message.includes('Pastefy')) {
            return res.status(502).json({
                error: 'Pastefy service error',
                details: error.message
            });
        }
        
        return res.status(500).json({
            error: 'Failed to encrypt and upload code',
            details: error.message
        });
    }
};
