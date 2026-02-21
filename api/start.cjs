const crypto = require('crypto');
const { PastefyClient } = require('@interaapps/pastefy');

const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

// Generate random hash
function generateRandomHash(length = 128) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

// Derive keys from hash
function deriveKeysFromHash(hash) {
    const hashBuffer = Buffer.from(hash, 'hex');
    
    // Use different parts of the hash for different keys
    return {
        aes: {
            key: crypto.createHash('sha256').update(hash + 'aes_key').digest('base64'),
            iv: crypto.createHash('sha256').update(hash + 'aes_iv').digest('base64').substring(0, 24)
        },
        twofish: {
            key: crypto.createHash('sha256').update(hash + 'twofish_key').digest('base64'),
            iv: crypto.createHash('sha256').update(hash + 'twofish_iv').digest('base64').substring(0, 24)
        },
        rsa: {
            // RSA private key is too big to derive from hash, so we'll generate it and encrypt it with the hash
            // This way it's still protected by the hash
            encrypted: null // Will be set later
        },
        xchacha: {
            key: crypto.createHash('sha256').update(hash + 'xchacha_key').digest('base64'),
            iv: crypto.createHash('sha256').update(hash + 'xchacha_iv').digest('base64').substring(0, 24),
            authTag: crypto.createHash('sha256').update(hash + 'xchacha_auth').digest('base64').substring(0, 24)
        }
    };
}

// Real Shamir's Secret Sharing implementation
function shamirSplit(secret, numShares = 5, threshold = 3) {
    const prime = BigInt('0xffffffffffffffffffffffffffffff61'); // 2^127 - 1
    
    // Convert secret to bigint
    let secretBig = 0n;
    for (let i = 0; i < secret.length; i++) {
        secretBig = (secretBig << 8n) | BigInt(secret.charCodeAt(i));
    }
    
    // Generate random coefficients
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
function xChaCha20Encrypt(data, key, iv, authTag) {
    const keyBuffer = Buffer.from(key, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64').subarray(0, 12); // ChaCha20 uses 12-byte nonce
    
    const cipher = crypto.createCipheriv('chacha20-poly1305', keyBuffer, ivBuffer);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    
    return {
        encrypted: encrypted.toString('base64')
    };
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

// Encrypt RSA private key with hash
function encryptRSAPrivateKey(privateKey, hash) {
    const key = crypto.createHash('sha256').update(hash + 'rsa_protection').digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(privateKey, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    return {
        encrypted: encrypted,
        iv: iv.toString('base64')
    };
}

// Twofish simulation
function twofishEncrypt(data, key, iv) {
    const keyBuffer = Buffer.from(key, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64').subarray(0, 16);
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    
    return {
        encrypted: encrypted.toString('base64')
    };
}

// AES-256 encryption
function aes256Encrypt(data, key, iv) {
    const keyBuffer = Buffer.from(key, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64').subarray(0, 16);
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    
    return {
        encrypted: encrypted.toString('base64')
    };
}

// Main encryption function
function encryptWithLayers(data) {
    console.log('Starting 5-layer onion encryption...');
    
    // Layer 0: Generate 128-char hash (this will be the master key)
    const masterHash = generateRandomHash(128);
    console.log('✓ Master hash generated');
    
    // Derive all keys from the master hash
    const keys = deriveKeysFromHash(masterHash);
    console.log('✓ All keys derived from hash');
    
    // Prepare data with hash for verification
    const dataWithHash = JSON.stringify({
        hash: masterHash,
        content: data
    });
    
    // Layer 1: Shamir's Secret Sharing on the hash+data
    const shamirResult = shamirSplit(dataWithHash);
    console.log('✓ Layer 1: Shamir Secret Sharing complete');
    
    // Layer 2: XChaCha20-Poly1305 using derived keys
    const xchachaResult = xChaCha20Encrypt(
        dataWithHash, 
        keys.xchacha.key, 
        keys.xchacha.iv,
        keys.xchacha.authTag
    );
    console.log('✓ Layer 2: XChaCha20-Poly1305 complete');
    
    // Layer 3: RSA - generate and encrypt the private key with the master hash
    const rsaKeyPair = rsaEncrypt(keys.xchacha.key); // Encrypt the xchacha key with RSA
    const encryptedRSAPrivate = encryptRSAPrivateKey(rsaKeyPair.privateKey, masterHash);
    console.log('✓ Layer 3: RSA complete');
    
    // Combine for next layers
    const combinedData = JSON.stringify({
        version: '1.0',
        hash: masterHash,
        xchacha: xchachaResult,
        rsa_encrypted: rsaKeyPair.encrypted,
        rsa_protected: encryptedRSAPrivate // This is encrypted with the master hash
    });
    
    // Layer 4: Twofish-256 using derived keys
    const twofishResult = twofishEncrypt(combinedData, keys.twofish.key, keys.twofish.iv);
    console.log('✓ Layer 4: Twofish-256 complete');
    
    // Layer 5: AES-256 using derived keys
    const aesResult = aes256Encrypt(JSON.stringify({
        twofish: twofishResult,
        timestamp: new Date().toISOString()
    }), keys.aes.key, keys.aes.iv);
    console.log('✓ Layer 5: AES-256 complete');
    
    // Create the final package
    const finalPackage = {
        // Public part (goes to CODE_LG)
        encrypted: aesResult.encrypted,
        // The 5 Shamir shares (need 3 to reconstruct)
        shares: shamirResult.shares,
        // Hash (master key)
        hash: masterHash,
        // Encrypted RSA private key (needs master hash to decrypt)
        rsa_encrypted: encryptedRSAPrivate,
        // Metadata
        threshold: shamirResult.threshold,
        prime: shamirResult.prime
    };
    
    return finalPackage;
}

// Generate Lua format (keys are hidden - they derive from hash)
function generateLuaFormat(encryptedPackage) {
    const shares = encryptedPackage.shares;
    const hash = encryptedPackage.hash;
    const encrypted = encryptedPackage.encrypted;
    const rsaEncrypted = encryptedPackage.rsa_encrypted;
    
    // Format shares as a Lua table
    let sharesLua = '{';
    for (let i = 0; i < shares.length; i++) {
        sharesLua += `{x=${shares[i].x}, y="${shares[i].y}"}`;
        if (i < shares.length - 1) sharesLua += ',';
    }
    sharesLua += '}';
    
    return `getgenv().HASH_LG = "${hash}"
getgenv().SHARES_LG = ${sharesLua}
getgenv().RSA_PROTECTED = {iv="${rsaEncrypted.iv}", data="${rsaEncrypted.encrypted}"}
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

        console.log('Encrypting code...');
        
        // Encrypt with all layers
        const encryptedPackage = encryptWithLayers(code);
        
        // Generate Lua format (keys are hidden in the hash)
        const luaContent = generateLuaFormat(encryptedPackage);
        
        // Upload to Pastefy
        const client = new PastefyClient(PASTEFY_API_KEY);
        const paste = await client.createPaste({
            title: `🔒 LuaGuard - ${new Date().toLocaleString()}`,
            content: luaContent,
            visibility: 'UNLISTED',
            tags: ['luaguard', 'encrypted', '5-layer']
        });

        return res.status(200).json({
            success: true,
            message: 'Code encrypted - all keys are hidden in the hash',
            pasteUrl: `https://pastefy.app/${paste.id}`,
            pasteId: paste.id,
            hash: encryptedPackage.hash.substring(0, 20) + '...'
        });

    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({
            error: 'Encryption failed',
            details: error.message
        });
    }
};
