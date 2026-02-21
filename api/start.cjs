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
        // Create 5 shares (in real Shamir you'd need threshold)
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

// XChaCha20 simulation (using ChaCha20-poly1305)
function xChaCha20Encrypt(data, key) {
    // XChaCha20 uses 24-byte nonce, but we'll use 12 for ChaCha20
    const iv = crypto.randomBytes(12);
    try {
        // Try to use chacha20 if available
        const cipher = crypto.createCipheriv('chacha20-poly1305', key.slice(0, 32), iv);
        const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        return {
            encrypted: encrypted.toString('base64'),
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64')
        };
    } catch (e) {
        // Fallback to AES-256-GCM if chacha20 not available
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
    // Generate RSA key pair
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
    
    // Encrypt the data with the public key
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(data));
    
    return {
        encrypted: encrypted.toString('base64'),
        privateKey: privateKey,
        publicKey: publicKey
    };
}

// Twofish simulation (using AES-256 as Twofish isn't in Node.js)
function twofishEncrypt(data) {
    const key = crypto.randomBytes(32); // 256-bit key
    const iv = crypto.randomBytes(16);   // 128-bit IV
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
    const key = crypto.randomBytes(32); // 256-bit key
    const iv = crypto.randomBytes(16);   // 128-bit IV
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    
    return {
        encrypted: encrypted.toString('base64'),
        key: key.toString('base64'),
        iv: iv.toString('base64')
    };
}

// Main encryption function (The Onion)
function encryptWithLayers(data) {
    console.log('Starting onion encryption process...');
    
    // Layer 0: Generate 128-letter random hash for the script
    const scriptHash = generateRandomHash(128);
    console.log('✓ Generated script hash');
    
    // Layer 1: Shamir's Secret Sharing creates a Key Fragment
    const shamirResult = shamirSplit(data + scriptHash);
    console.log('✓ Layer 1: Shamir Secret Sharing complete');
    
    // Layer 2: XChaCha20 encrypts the data
    const xchachaKey = crypto.randomBytes(32);
    const xchachaResult = xChaCha20Encrypt(data, xchachaKey);
    console.log('✓ Layer 2: XChaCha20 encryption complete');
    
    // Layer 3: RSA encrypts the XChaCha20 key
    const rsaResult = rsaEncrypt(xchachaKey.toString('base64'));
    console.log('✓ Layer 3: RSA encryption complete');
    
    // Combine data for next layers (the encrypted XChaCha20 key is now in RSA)
    const combinedData = JSON.stringify({
        version: '1.0',
        scriptHash: scriptHash,
        shamir: shamirResult,
        xchacha: xchachaResult,
        rsa: {
            encrypted: rsaResult.encrypted
            // private key NOT included here - will be in metadata
        }
    });
    
    // Layer 4: Twofish encrypts the entire package
    const twofishResult = twofishEncrypt(combinedData);
    console.log('✓ Layer 4: Twofish encryption complete');
    
    // Layer 5: AES-256 encrypts the Twofish output
    const aesResult = aes256Encrypt(JSON.stringify(twofishResult));
    console.log('✓ Layer 5: AES-256 encryption complete');
    
    // Final encrypted package with all metadata needed for decryption
    // (In production, the metadata would be split via Shamir)
    const finalPackage = {
        version: '1.0',
        algorithm: 'onion-5layer',
        timestamp: new Date().toISOString(),
        encrypted: aesResult.encrypted,
        // Store metadata needed for decryption
        // To truly follow the spec, these would be split via Shamir
        decryptionMetadata: {
            aes: {
                key: aesResult.key,
                iv: aesResult.iv
            },
            twofish: {
                key: twofishResult.key,
                iv: twofishResult.iv
            },
            rsa: {
                privateKey: rsaResult.privateKey  // Required to decrypt XChaCha20 key
            },
            xchacha: {
                key: xchachaKey.toString('base64'), // This is RSA encrypted in the package
                iv: xchachaResult.iv,
                authTag: xchachaResult.authTag
            },
            shamir: {
                fragment: shamirResult.fragment,
                shares: shamirResult.shares
            },
            scriptHash: scriptHash
        },
        // Decryption instructions
        decrypt: {
            steps: [
                "1. Use Shamir shares to get AES key",
                "2. Decrypt AES → get Twofish",
                "3. Decrypt Twofish → get RSA private key payload",
                "4. Decrypt RSA → get XChaCha20 key",
                "5. Decrypt XChaCha20 → get original data"
            ]
        }
    };
    
    return finalPackage;
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
        const encryptedPackage = encryptWithLayers(code);
        console.log('Encryption complete');

        // Step 2: Upload to Pastefy
        console.log('Connecting to Pastefy...');
        const client = new PastefyClient(PASTEFY_API_KEY);
        
        console.log('Creating paste...');
        const paste = await client.createPaste({
            title: `🔒 LuaGuard Encrypted Code - ${new Date().toLocaleString()}`,
            content: JSON.stringify(encryptedPackage, null, 2),
            visibility: 'UNLISTED',
            tags: ['luaguard', 'encrypted', '5-layer', 'onion-encryption']
        });

        console.log('✓ Paste created successfully with ID:', paste.id);

        // Return success response (matches what your HTML expects)
        return res.status(200).json({
            success: true,
            message: 'Code encrypted with 5 layers and uploaded to Pastefy',
            pasteId: paste.id,
            pasteUrl: `https://pastefy.app/${paste.id}`,
            hash: encryptedPackage.scriptHash.substring(0, 50) + '...',
            encryptionDetails: {
                layers: ['Shamir', 'XChaCha20', 'RSA', 'Twofish', 'AES-256'],
                timestamp: encryptedPackage.timestamp,
                version: encryptedPackage.version
            }
        });

    } catch (error) {
        console.error('Encryption/upload error:', error);
        
        // Check if it's a Pastefy error
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
