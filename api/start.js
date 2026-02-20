// api/start.js
import fs from 'fs/promises';
import path from 'path';

// Generate a random 32-character hash
function generateHash() {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let hash = '';
    for (let i = 0; i < 32; i++) {
        hash += chars[Math.floor(Math.random() * chars.length)];
    }
    return hash;
}

// Generate 10 random letters for filename
function generateFilename() {
    const letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let filename = '';
    for (let i = 0; i < 10; i++) {
        filename += letters[Math.floor(Math.random() * letters.length)];
    }
    return filename;
}

// Generate 16 random passwords
function generatePasswords() {
    const passwords = [];
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    
    for (let i = 0; i < 16; i++) {
        let password = '';
        const length = Math.floor(Math.random() * 12) + 8; // 8-20 characters
        for (let j = 0; j < length; j++) {
            password += chars[Math.floor(Math.random() * chars.length)];
        }
        passwords.push(password);
    }
    return passwords;
}

// Select password based on hash signal
function selectPassword(hash, passwords) {
    // Use the hash to determine which password to use
    // Convert first 4 chars of hash to a number between 0-15
    const hashSignal = parseInt(hash.substring(0, 4), 36) % 16;
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
    // Convert each character to its ASCII code and join with separators
    let result = [];
    for (let i = 0; i < str.length; i++) {
        result.push(str.charCodeAt(i).toString());
    }
    return result.join('|');
}

function xorEncode(str, key) {
    // Simple XOR encryption
    let result = '';
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i) ^ key.charCodeAt(i % key.length);
        result += String.fromCharCode(charCode);
    }
    return result;
}

function base86Encode(str) {
    // Custom base86 encoding (using printable ASCII range 32-117)
    const bytes = Buffer.from(str);
    let result = '';
    
    for (let i = 0; i < bytes.length; i++) {
        // Map 0-255 to 32-117 range (86 possible values)
        const b1 = Math.floor(bytes[i] / 86) + 32;
        const b2 = (bytes[i] % 86) + 32;
        result += String.fromCharCode(b1) + String.fromCharCode(b2);
    }
    
    return result;
}

function reverseEncode(str) {
    // Reverse the string as the final layer
    return str.split('').reverse().join('');
}

// Main encryption function
function encryptCode(code, password) {
    let encrypted = code;
    
    // Layer 1: Base64
    encrypted = base64Encode(encrypted);
    console.log('After Base64:', encrypted);
    
    // Layer 2: Numerical encoding
    encrypted = numericalEncode(encrypted);
    console.log('After Numerical:', encrypted);
    
    // Layer 3: XOR with password
    encrypted = xorEncode(encrypted, password);
    console.log('After XOR:', encrypted);
    
    // Layer 4: Base86
    encrypted = base86Encode(encrypted);
    console.log('After Base86:', encrypted);
    
    // Layer 5: Reverse (final layer)
    encrypted = reverseEncode(encrypted);
    console.log('After Reverse:', encrypted);
    
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
        const filePath = path.join(process.cwd(), 'out', `${filename}.luau`);
        
        // Ensure the out directory exists
        try {
            await fs.mkdir(path.join(process.cwd(), 'out'), { recursive: true });
        } catch (err) {
            // Directory might already exist, ignore error
        }
        
        // Write the file
        await fs.writeFile(filePath, fileContent, 'utf8');
        
        // For Vercel, we need to store the file in /tmp for serverless functions
        // But since you want /out, we'll create it and provide the URL to access it
        // Note: In Vercel serverless functions, you can only write to /tmp
        // So we'll write to /tmp/out instead and provide the filename
        
        const tmpFilePath = path.join('/tmp', 'out', `${filename}.luau`);
        try {
            await fs.mkdir(path.join('/tmp', 'out'), { recursive: true });
        } catch (err) {
            // Directory might already exist, ignore error
        }
        await fs.writeFile(tmpFilePath, fileContent, 'utf8');
        
        // Create URLs for accessing the file
        const fileUrl = `/out/${filename}.luau`;
        const tmpFileUrl = `/api/get-file?file=${filename}.luau`; // You'd need to create this endpoint
        
        // Store passwords mapping securely (in production, use a database)
        // For now, we'll store in /tmp (will be lost on function cold start)
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
            timestamp: Date.now()
        };
        await fs.writeFile(passwordsPath, JSON.stringify(passwordsMap), 'utf8');
        
        return res.status(200).json({
            success: true,
            hash: hash,
            filename: `${filename}.luau`,
            fileUrl: fileUrl,
            downloadUrl: `/api/download/${filename}.luau`, // You'd need to create this endpoint
            message: 'Code encrypted and saved successfully',
            // Include these for debugging (remove in production)
            debug: {
                usedPasswordIndex: signal,
                filePath: filePath,
                tmpPath: tmpFilePath
            }
        });
        
    } catch (error) {
        console.error('Encryption error:', error);
        return res.status(500).json({ 
            error: 'Failed to encrypt code',
            details: error.message 
        });
    }
}
