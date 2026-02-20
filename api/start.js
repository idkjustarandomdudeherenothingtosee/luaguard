// api/start.js
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

// Generate a random 32-character hash
function generateHash() {
    return crypto.randomBytes(16).toString('hex'); // 32 hex characters
}

// Generate 10 random letters for filename
function generateFilename() {
    return crypto.randomBytes(5).toString('hex'); // 10 hex characters
}

// Generate 16 random passwords
function generatePasswords() {
    const passwords = [];
    for (let i = 0; i < 16; i++) {
        passwords.push(crypto.randomBytes(16).toString('base64'));
    }
    return passwords;
}

// Select password based on hash signal
function selectPassword(hash, passwords) {
    const hashSignal = parseInt(hash.substring(0, 8), 16) % 16;
    return {
        password: passwords[hashSignal],
        signal: hashSignal
    };
}

// Encryption layers
function base64Encode(str) {
    return Buffer.from(str).toString('base64');
}

function numericalEncode(str) {
    let result = [];
    for (let i = 0; i < str.length; i++) {
        result.push(str.charCodeAt(i).toString());
    }
    return result.join('|');
}

function xorEncode(str, key) {
    let result = '';
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i) ^ key.charCodeAt(i % key.length);
        result += String.fromCharCode(charCode);
    }
    return Buffer.from(result).toString('base64'); // Convert to safe string
}

function base86Encode(str) {
    const bytes = Buffer.from(str);
    let result = '';
    
    for (let i = 0; i < bytes.length; i++) {
        const b1 = Math.floor(bytes[i] / 86) + 32;
        const b2 = (bytes[i] % 86) + 32;
        result += String.fromCharCode(b1) + String.fromCharCode(b2);
    }
    
    return result;
}

function atbashEncode(str) {
    // Atbash cipher as the final layer
    let result = '';
    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (char.match(/[a-z]/)) {
            // a->z, b->y, etc.
            result += String.fromCharCode(219 - char.charCodeAt(0));
        } else if (char.match(/[A-Z]/)) {
            // A->Z, B->Y, etc.
            result += String.fromCharCode(155 - char.charCodeAt(0));
        } else {
            result += char;
        }
    }
    return result;
}

// Main encryption function
function encryptCode(code, password) {
    let encrypted = code;
    
    // Layer 1: Base64
    encrypted = base64Encode(encrypted);
    
    // Layer 2: Numerical encoding
    encrypted = numericalEncode(encrypted);
    
    // Layer 3: XOR with password
    encrypted = xorEncode(encrypted, password);
    
    // Layer 4: Base86
    encrypted = base86Encode(encrypted);
    
    // Layer 5: Atbash cipher (final layer)
    encrypted = atbashEncode(encrypted);
    
    return encrypted;
}

// Vercel serverless function handler
export default async function handler(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight request
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    // Only allow POST requests
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }
    
    try {
        const { code } = req.body;
        
        if (!code) {
            return res.status(400).json({ error: 'No code provided' });
        }
        
        // Generate hash and passwords
        const hash = generateHash();
        const passwords = generatePasswords();
        
        // Select password based on hash
        const { password, signal } = selectPassword(hash, passwords);
        
        // Encrypt the code
        const encryptedCode = encryptCode(code, password);
        
        // Prepare the content for the file
        const fileContent = `getgenv().code_hash = "${hash}"\n\n-- Encrypted code (password signal: ${signal})\n${encryptedCode}`;
        
        // Generate filename (10 random letters)
        const filename = generateFilename();
        
        // Use /tmp for Vercel serverless functions (writable)
        const tmpDir = path.join('/tmp', 'out');
        const filePath = path.join(tmpDir, `${filename}.luau`);
        
        // Ensure the directory exists
        await fs.mkdir(tmpDir, { recursive: true });
        
        // Write the file
        await fs.writeFile(filePath, fileContent, 'utf8');
        
        // Store passwords mapping in /tmp (temporary storage)
        const passwordsPath = path.join('/tmp', 'passwords.json');
        let passwordsMap = {};
        try {
            const existing = await fs.readFile(passwordsPath, 'utf8');
            passwordsMap = JSON.parse(existing);
        } catch {
            passwordsMap = {};
        }
        
        passwordsMap[hash] = {
            passwords,
            filename: `${filename}.luau`,
            signal: signal,
            timestamp: Date.now()
        };
        
        await fs.writeFile(passwordsPath, JSON.stringify(passwordsMap), 'utf8');
        
        // Return success response with file info
        return res.status(200).json({
            success: true,
            hash: hash,
            filename: `${filename}.luau`,
            message: 'Code encrypted and saved successfully',
            downloadUrl: `/api/get-file?file=${filename}.luau`, // You'll need to create this endpoint
            note: 'File saved in /tmp/out (temporary storage)'
        });
        
    } catch (error) {
        console.error('Encryption error:', error);
        return res.status(500).json({ 
            error: 'Failed to encrypt code',
            details: error.message 
        });
    }
}
