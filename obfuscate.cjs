// api/start.cjs
const fs = require('fs');
const path = require('path');
const os = require('os');
const { createWriteStream } = require('fs');
const { Readable } = require('stream');
const FormData = require('form-data');

const API_KEY = 'wynf_ew84z6L93odfnAc017sZaJdOVTwPBvH0'; // Make sure to set this in your environment variables
const BASE_URL = 'https://wynfuscate.com/api/v1';

module.exports = async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight request
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  let tempFilePath = null;

  try {
    const { code } = req.body;

    // Validate input
    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    if (typeof code !== 'string') {
      return res.status(400).json({ error: 'Code must be a string' });
    }

    // Create temporary file
    const tempDir = os.tmpdir();
    tempFilePath = path.join(tempDir, `script_${Date.now()}.lua`);
    
    // Write code to temporary file
    fs.writeFileSync(tempFilePath, code);

    // Prepare form data with fixed options: ROBLOX_COMPAT and enhanced compression
    const form = new FormData();
    form.append('file', fs.createReadStream(tempFilePath));
    form.append('targetPlatform', 'ROBLOX_COMPAT');
    form.append('enhancedCompression', 'true');

    // Submit to Wynfuscate API
    const submitResponse = await fetch(`${BASE_URL}/obfuscate`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.WYNFUSCATE_API_KEY || API_KEY}`,
        ...form.getHeaders()
      },
      body: form,
    });

    if (!submitResponse.ok) {
      const errorText = await submitResponse.text();
      throw new Error(`Submission failed: ${errorText}`);
    }

    const job = await submitResponse.json();
    console.log(`Job submitted: ${job.id}`);

    // Poll for completion
    let pollInterval = 2000;
    const maxInterval = 30000;
    const maxPolls = 60;
    let jobStatus = null;

    for (let polls = 0; polls < maxPolls; polls++) {
      const statusResponse = await fetch(`${BASE_URL}/jobs/${job.id}`, {
        headers: {
          'Authorization': `Bearer ${process.env.WYNFUSCATE_API_KEY || API_KEY}`
        }
      });

      if (!statusResponse.ok) {
        const errorText = await statusResponse.text();
        throw new Error(`Status check failed: ${errorText}`);
      }

      jobStatus = await statusResponse.json();

      if (jobStatus.status === 'completed') {
        console.log(`Completed in ${jobStatus.processingTimeMs}ms`);
        break;
      } else if (jobStatus.status === 'failed') {
        throw new Error(`Job failed: ${jobStatus.error?.message || 'Unknown error'}`);
      }

      await new Promise(r => setTimeout(r, pollInterval));
      pollInterval = Math.min(pollInterval * 1.5, maxInterval);
    }

    if (!jobStatus || jobStatus.status !== 'completed') {
      throw new Error('Job timed out');
    }

    // Download the obfuscated result
    const downloadResponse = await fetch(`${BASE_URL}/jobs/${job.id}/download`, {
      headers: {
        'Authorization': `Bearer ${process.env.WYNFUSCATE_API_KEY || API_KEY}`
      }
    });

    if (!downloadResponse.ok) {
      const errorText = await downloadResponse.text();
      throw new Error(`Download failed: ${errorText}`);
    }

    const obfuscatedBuffer = Buffer.from(await downloadResponse.arrayBuffer());
    const obfuscatedCode = obfuscatedBuffer.toString('utf-8');

    // Clean up temp file
    try {
      fs.unlinkSync(tempFilePath);
    } catch (cleanupError) {
      console.error('Failed to clean up temp file:', cleanupError);
    }

    // Return the obfuscated code
    return res.status(200).json({
      success: true,
      obfuscatedCode: obfuscatedCode,
      jobId: job.id,
      processingTime: jobStatus.processingTimeMs
    });

  } catch (error) {
    console.error('Obfuscation error:', error);

    // Clean up temp file if it exists
    if (tempFilePath) {
      try {
        fs.unlinkSync(tempFilePath);
      } catch (cleanupError) {
        console.error('Failed to clean up temp file:', cleanupError);
      }
    }

    // Return error response
    return res.status(500).json({
      success: false,
      error: error.message || 'Internal server error'
    });
  }
};
