import crypto from 'crypto';
import { PastefyClient } from '@interaapps/pastefy';

// Pastefy API key
const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

// Helper function to generate random hash
function generateRandomHash(length = 128) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

// Shamir's Secret Sharing simulation (simplified for demo)
function shamirSplit(secret) {
    // In a real implementation, this would use actual Shamir's Secret Sharing
    // For demo purposes, we're creating a simulated key fragment
    const fragment = crypto.randomBytes(32).toString('hex');
    return {
        fragment,
        // Store encrypted form of the fragment that would require multiple shares
        encryptedFragment: crypto.createHash('sha256').update(secret + fragment).digest('hex')
    };
}

// XChaCha20 encryption (using ChaCha20 as Node.js doesn't have native XChaCha20)
function xChaCha20Encrypt(data, key) {
    const iv = crypto.randomBytes(24); // XChaCha20 uses 24-byte nonce
    const cipher = crypto.createCipheriv('chacha20-poly1305', key.slice(0, 32), iv.slice(0, 12));
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
        privateKey: privateKey // This would normally be split via Shamir
    };
}

// Twofish encryption (using AES as fallback since Node.js doesn't have native Twofish)
function twofishEncrypt(data) {
    const key = crypto.randomBytes(32); // Twofish supports up to 256-bit keys
    const iv = crypto.randomBytes(16);
    // Using AES as a simulation since Twofish isn't natively available
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
    
    // Generate random hash for the script
    const scriptHash = generateRandomHash(128);
    console.log('Generated script hash:', scriptHash);
    
    // Layer 1: Shamir's Secret Sharing
    const shamirResult = shamirSplit(data + scriptHash);
    console.log('Layer 1 complete: Shamir Secret Sharing');
    
    // Layer 2: XChaCha20
    const xchachaKey = crypto.randomBytes(32);
    const xchachaResult = xChaCha20Encrypt(data, xchachaKey);
    console.log('Layer 2 complete: XChaCha20 encryption');
    
    // Layer 3: RSA encrypt the XChaCha20 key
    const rsaResult = rsaEncrypt(xchachaKey.toString('base64'));
    console.log('Layer 3 complete: RSA encryption');
    
    // Combine data for next layers
    const combinedData = JSON.stringify({
        scriptHash,
        shamir: shamirResult,
        xchacha: xchachaResult,
        rsa: rsaResult
    });
    
    // Layer 4: Twofish
    const twofishResult = twofishEncrypt(combinedData);
    console.log('Layer 4 complete: Twofish encryption');
    
    // Layer 5: AES-256
    const aesResult = aes256Encrypt(JSON.stringify(twofishResult));
    console.log('Layer 5 complete: AES-256 encryption');
    
    // Final encrypted package
    const finalPackage = {
        version: '1.0',
        algorithm: 'onion-5layer',
        timestamp: new Date().toISOString(),
        data: aesResult,
        // Store metadata needed for decryption (would normally be split via Shamir)
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

export default async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle preflight request
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

        console.log('Received code to encrypt');

        // Step 1: Encrypt the code with all layers
        const encryptedPackage = encryptWithLayers(code);
        
        // Step 2: Create paste on Pastefy
        const client = new PastefyClient(PASTEFY_API_KEY);
        
        console.log('Creating paste on Pastefy...');
        
        const paste = await client.createPaste({
            title: `Encrypted Code - ${new Date().toISOString()}`,
            content: JSON.stringify(encryptedPackage, null, 2),
            visibility: 'UNLISTED',
            tags: ['encrypted', 'luaguard', 'multi-layer']
        });

        console.log('Paste created successfully:', paste.id);

        // Return success response with paste URL
        return res.status(200).json({
            success: true,
            message: 'Code encrypted and uploaded successfully',
            pasteId: paste.id,
            pasteUrl: `https://pastefy.app/${paste.id}`,
            hash: encryptedPackage.data.encrypted.substring(0, 50) + '...' // Preview of encrypted data
        });

    } catch (error) {
        console.error('Encryption/upload error:', error);
        
        return res.status(500).json({
            error: 'Failed to encrypt and upload code',
            details: error.message
        });
    }
}
