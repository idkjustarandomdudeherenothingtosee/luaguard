const crypto = require('crypto');
const { PastefyClient } = require('@interaapps/pastefy');

const PASTEFY_API_KEY = '2K0kaS4rVTo11xKKp6JnlFROwAqFuBo817OxI0TIBX2QjOxawim3mBiEuPuj';

function generateHashWithKey() {
    const hash = crypto.randomBytes(64).toString('hex');
    const key = crypto.randomBytes(4).toString('hex');
    const finalHash = hash.slice(0, 57) + key + hash.slice(57);
    return { fullHash: finalHash, key: key, hashWithoutKey: hash };
}

function aesEncrypt(data, key) {
    const keyBuffer = crypto.createHash('sha256').update(key).digest();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return { encrypted: encrypted, iv: iv.toString('base64'), key: key };
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
        if (!code) return res.status(400).json({ error: 'Code is required' });

        const { fullHash, key, hashWithoutKey } = generateHashWithKey();
        const dataToEncrypt = JSON.stringify({ hash: hashWithoutKey, content: code });
        const aesResult = aesEncrypt(dataToEncrypt, key);
        
        const client = new PastefyClient(PASTEFY_API_KEY);
        const luaContent = `getgenv().HASH_LG = "${fullHash}"
getgenv().CODE_LG = "${aesResult.encrypted}"
getgenv().IV_LG = "${aesResult.iv}"`;

        const paste = await client.createPaste({
            title: `🔒 LuaGuard - ${new Date().toLocaleString()}`,
            content: luaContent,
            visibility: 'UNLISTED',
            tags: ['luaguard', 'aes-256']
        });

        res.status(200).json({ success: true, pasteUrl: `https://pastefy.app/${paste.id}` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
