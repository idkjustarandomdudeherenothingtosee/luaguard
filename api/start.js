const crypto = require('crypto');

// Simple encryption without external dependencies first
function generateRandomHash(length = 128) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

// Simple AES encryption
function encryptWithAES(data) {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    return {
        encrypted,
        key: key.toString('base64'),
        iv: iv.toString('base64')
    };
}

module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    // Handle preflight
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Test GET
    if (req.method === 'GET') {
        return res.status(200).json({ 
            status: 'ok', 
            message: 'LuaGuard API is running'
        });
    }

    // Handle POST
    if (req.method === 'POST') {
        try {
            console.log('Processing encryption request');
            
            // Parse body
            let body = req.body;
            if (typeof body === 'string') {
                body = JSON.parse(body);
            }

            const { code } = body || {};
            
            if (!code) {
                return res.status(400).json({ error: 'Code is required' });
            }

            // Generate hash
            const hash = generateRandomHash(128);
            
            // Encrypt the code
            const encrypted = encryptWithAES(code);
            
            // Create paste data
            const pasteData = {
                id: hash.substring(0, 8),
                hash: hash,
                data: encrypted.encrypted,
                key: encrypted.key,
                iv: encrypted.iv,
                timestamp: new Date().toISOString()
            };

            // For now, just return the data (Pastefy integration removed for debugging)
            return res.status(200).json({
                success: true,
                message: 'Code encrypted successfully',
                pasteId: hash.substring(0, 8),
                pasteUrl: `https://pastefy.app/${hash.substring(0, 8)}`, // Simulated URL
                data: pasteData
            });

        } catch (error) {
            console.error('Error:', error);
            return res.status(500).json({ 
                error: 'Encryption failed', 
                details: error.message 
            });
        }
    }

    return res.status(405).json({ error: 'Method not allowed' });
};
