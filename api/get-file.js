// api/get-file.js
import fs from 'fs/promises';
import path from 'path';

export default async function handler(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    const { file } = req.query;
    
    if (!file) {
        return res.status(400).json({ error: 'No file specified' });
    }
    
    try {
        // Sanitize filename to prevent directory traversal
        const sanitizedFile = path.basename(file);
        const filePath = path.join('/tmp', 'out', sanitizedFile);
        
        const content = await fs.readFile(filePath, 'utf8');
        
        // Set headers for file download
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename="${sanitizedFile}"`);
        
        return res.status(200).send(content);
        
    } catch (error) {
        if (error.code === 'ENOENT') {
            return res.status(404).json({ error: 'File not found' });
        }
        
        console.error('Download error:', error);
        return res.status(500).json({ error: 'Failed to download file' });
    }
}
