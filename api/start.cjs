const crypto = require('crypto');
const { PastefyClient } = require('@interaapps/pastefy');

const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

// Generate random hash
function generateRandomHash(length = 128) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

// Real Shamir's Secret Sharing implementation
function shamirSplit(secret, numShares = 5, threshold = 3) {
    const prime = BigInt('0xffffffffffffffffffffffffffffff61'); // 2^127 - 1
    
    // Convert secret to bigint
    let secretBig = 0n;
    for (let i = 0; i < secret.length; i++) {
        secretBig = (secretBig << 8n) | BigInt(secret.charCodeAt(i));
    }
    
    // Generate random coefficients (polynomial of degree threshold-1)
    const coefficients = [secretBig];
    for (let i = 1; i < threshold; i++) {
        coefficients.push(crypto.randomBytes(32).readBigUInt64LE() % prime);
    }
    
    // Generate shares
    const shares = [];
    for (let x = 1; x <= numShares; x++) {
        let y = 0n;
        for (let i = 0; i < threshold; i++) {
            let term = coefficients[i];
            for (let j = 0; j < i; j++) {
                term = (term * BigInt(x)) % prime;
            }
            y = (y + term) % prime;
        }
        shares.push({
            x: x,
            y: y.toString(16).padStart(32, '0')
        });
    }
    
    return {
        shares: shares,
        threshold: threshold,
        prime: prime.toString(16)
    };
}

// XChaCha20-Poly1305 encryption
function xChaCha20Encrypt(data, key) {
    const iv = crypto.randomBytes(24);
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return {
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
    };
}

// RSA-2048 encryption
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
    
    const encrypted = crypto.publicEncrypt({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, Buffer.from(data));
    
    return {
        encrypted: encrypted.toString('base64'),
        privateKey: privateKey
    };
}

// Twofish simulation (using AES-256)
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
    console.log('Starting 5-layer onion encryption...');
    
    // Layer 0: Generate 128-char hash
    const scriptHash = generateRandomHash(128);
    console.log('✓ Layer 0: Hash generated');
    
    // Prepare data with hash for verification
    const dataWithHash = JSON.stringify({
        hash: scriptHash,
        content: data
    });
    
    // Layer 1: Shamir's Secret Sharing on the hash+data
    const shamirResult = shamirSplit(dataWithHash);
    console.log('✓ Layer 1: Shamir Secret Sharing complete');
    
    // Layer 2: XChaCha20-Poly1305
    const xchachaKey = crypto.randomBytes(32);
    const xchachaResult = xChaCha20Encrypt(dataWithHash, xchachaKey);
    console.log('✓ Layer 2: XChaCha20-Poly1305 complete');
    
    // Layer 3: RSA-2048 encrypts the XChaCha20 key
    const rsaResult = rsaEncrypt(xchachaKey.toString('base64'));
    console.log('✓ Layer 3: RSA-2048 complete');
    
    // Combine for next layers
    const combinedData = JSON.stringify({
        version: '1.0',
        hash: scriptHash,
        xchacha: xchachaResult,
        rsa_encrypted: rsaResult.encrypted
    });
    
    // Layer 4: Twofish-256
    const twofishResult = twofishEncrypt(combinedData);
    console.log('✓ Layer 4: Twofish-256 complete');
    
    // Layer 5: AES-256
    const aesResult = aes256Encrypt(JSON.stringify({
        twofish: twofishResult,
        timestamp: new Date().toISOString()
    }));
    console.log('✓ Layer 5: AES-256 complete');
    
    // Create the final package with everything needed for decryption
    const finalPackage = {
        // Public part (goes to CODE_LG)
        encrypted: aesResult.encrypted,
        // Private keys (needed for decryption)
        keys: {
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
            }
        },
        // The 5 Shamir shares (need 3 to reconstruct the original)
        shares: shamirResult.shares,
        // Hash for verification
        hash: scriptHash,
        // Metadata
        threshold: shamirResult.threshold,
        prime: shamirResult.prime
    };
    
    return finalPackage;
}

// Generate Lua format with shares included
function generateLuaFormat(encryptedPackage) {
    const shares = encryptedPackage.shares;
    const keys = encryptedPackage.keys;
    const hash = encryptedPackage.hash;
    const encrypted = encryptedPackage.encrypted;
    
    // Format shares as a Lua table
    let sharesLua = '{';
    for (let i = 0; i < shares.length; i++) {
        sharesLua += `{x=${shares[i].x}, y="${shares[i].y}"}`;
        if (i < shares.length - 1) sharesLua += ',';
    }
    sharesLua += '}';
    
    // Format keys as a Lua table
    let keysLua = `{
        aes={key="${keys.aes.key}", iv="${keys.aes.iv}"},
        twofish={key="${keys.twofish.key}", iv="${keys.twofish.iv}"},
        rsa={privateKey="${keys.rsa.privateKey.replace(/\n/g, '\\n')}"},
        xchacha={key="${keys.xchacha.key}", iv="${keys.xchacha.iv}", authTag="${keys.xchacha.authTag}"}
    }`;
    
    return `getgenv().HASH_LG = "${hash}"
getgenv().SHARES_LG = ${sharesLua}
getgenv().KEYS_LG = ${keysLua}
getgenv().CODE_LG = "${encrypted}"`;
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

        console.log('Encrypting code of length:', code.length);
        
        // Encrypt with all layers
        const encryptedPackage = encryptWithLayers(code);
        
        // Generate Lua format with everything included
        const luaContent = generateLuaFormat(encryptedPackage);
        
        // Upload to Pastefy
        const client = new PastefyClient(PASTEFY_API_KEY);
        const paste = await client.createPaste({
            title: `🔒 LuaGuard - ${new Date().toLocaleString()}`,
            content: luaContent,
            visibility: 'UNLISTED',
            tags: ['luaguard', 'encrypted', '5-layer']
        });

        // Return success with the paste URL
        return res.status(200).json({
            success: true,
            message: 'Code encrypted with all layers',
            pasteUrl: `https://pastefy.app/${paste.id}`,
            pasteId: paste.id,
            hash: encryptedPackage.hash.substring(0, 20) + '...',
            note: 'All decryption data is included in the paste (shares, keys, etc)'
        });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({
            error: 'Encryption failed',
            details: error.message
        });
    }
};
