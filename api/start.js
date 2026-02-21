const crypto = require('crypto');
const { PastefyClient } = require('@interaapps/pastefy');

const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

function generateRandomHash(length = 128) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

// Simulated Shamir's Secret Sharing
function shamirSplit(secret) {
    const fragment = crypto.randomBytes(32).toString('hex');
    return {
        fragment,
        encryptedFragment: crypto.createHash('sha256').update(secret + fragment).digest('hex')
    };
}

// XChaCha20 simulation (using available algorithms)
function xChaCha20Encrypt(data, key) {
    const iv = crypto.randomBytes(16);
    // Use AES-256-GCM as fallback since chacha20 might not be available
    const cipher = crypto.createCipheriv('aes-256-gcm', key.slice(0, 32), iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return {
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
    };
}

// RSA encryption
function rsaEncrypt(data) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(data));
    
    return {
        encrypted: encrypted.toString('base64'),
        privateKey: privateKey
    };
}

// Twofish simulation (using AES as Twofish isn't available in Node.js)
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
    console.log('Starting encryption process...');
    
    // Layer 0: Generate hash
    const scriptHash = generateRandomHash(128);
    console.log('Generated script hash');
    
    // Layer 1: Shamir's Secret Sharing
    const shamirResult = shamirSplit(data + scriptHash);
    console.log('Layer 1 complete');
    
    // Layer 2: XChaCha20
    const xchachaKey = crypto.randomBytes(32);
    const xchachaResult = xChaCha20Encrypt(data, xchachaKey);
    console.log('Layer 2 complete');
    
    // Layer 3: RSA encrypt the XChaCha20 key
    const rsaResult = rsaEncrypt(xchachaKey.toString('base64'));
    console.log('Layer 3 complete');
    
    // Combine data for next layers
    const combinedData = JSON.stringify({
        scriptHash,
        shamir: shamirResult,
        xchacha: xchachaResult,
        rsa: {
            encrypted: rsaResult.encrypted
            // private key not included in this layer
        }
    });
    
    // Layer 4: Twofish
    const twofishResult = twofishEncrypt(combinedData);
    console.log('Layer 4 complete');
    
    // Layer 5: AES-256
    const aesResult = aes256Encrypt(JSON.stringify(twofishResult));
    console.log('Layer 5 complete');
    
    // Final encrypted package
    const finalPackage = {
        version: '1.0',
        algorithm: 'onion-5layer',
        timestamp: new Date().toISOString(),
        data: aesResult,
        // Metadata needed for decryption (in production, this would be split via Shamir)
        metadata: {
            shamirFragment: shamirResult.fragment,
            rsaPrivateKey: rsaResult.privateKey,
            twofishKey: twofishResult.key,
            twofishIv: twofishResult.iv,
            aesKey: aesResult.key,
            aesIv: aesResult.iv,
            xchachaKey: xchachaKey.toString('base64'),
            xchachaIv: xchachaResult.iv,
            xchachaAuthTag: xchachaResult.authTag
        }
    };
    
    return finalPackage;
}

module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    // Handle preflight request
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    // Handle GET request for testing
    if (req.method === 'GET') {
        return res.status(200).json({ 
            status: 'ok', 
            message: 'LuaGuard API is running',
            endpoints: {
                POST: '/api/start - Upload encrypted code'
            }
        });
    }

    // Only allow POST for actual encryption
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed. Use POST.' });
    }

    try {
        // Parse request body
        let body;
        try {
            body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
        } catch (e) {
            console.error('Failed to parse request body:', e);
            return res.status(400).json({ error: 'Invalid JSON in request body' });
        }

        const { code } = body;

        if (!code) {
            return res.status(400).json({ error: 'Code is required' });
        }

        if (typeof code !== 'string') {
            return res.status(400).json({ error: 'Code must be a string' });
        }

        console.log('Received code to encrypt, length:', code.length);

        // Step 1: Encrypt the code with all layers
        const encryptedPackage = encryptWithLayers(code);
        
        // Step 2: Create paste on Pastefy
        console.log('Initializing Pastefy client...');
        const client = new PastefyClient(PASTEFY_API_KEY);
        
        console.log('Creating paste on Pastefy...');
        
        const paste = await client.createPaste({
            title: `Encrypted Code - ${new Date().toISOString()}`,
            content: JSON.stringify(encryptedPackage, null, 2),
            visibility: 'UNLISTED',
            tags: ['encrypted', 'luaguard', 'multi-layer']
        });

        console.log('Paste created successfully:', paste.id);

        // Return success response
        return res.status(200).json({
            success: true,
            message: 'Code encrypted and uploaded successfully',
            pasteId: paste.id,
            pasteUrl: `https://pastefy.app/${paste.id}`,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Encryption/upload error:', error);
        
        // Determine error type and return appropriate status
        if (error.message.includes('Pastefy') || error.code === 'ECONNREFUSED') {
            return res.status(502).json({
                error: 'Failed to connect to Pastefy service',
                details: error.message
            });
        }
        
        return res.status(500).json({
            error: 'Failed to encrypt and upload code',
            details: error.message,
            type: error.constructor.name
        });
    }
};
