const fs = require('fs');
const FormData = require('form-data');

const API_KEY = 'wynf_your_api_key';
const BASE_URL = 'https://wynfuscate.com/api/v1';
const LUAGUARD_URL = 'https://luaguard-ochre.vercel.app/api/start.cjs';

async function obfuscateAndSend(filePath) {
  try {
    // 1. Obfuscate using Wynfuscator
    console.log('Obfuscating...');
    
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));
    form.append('targetPlatform', 'ROBLOX_COMPAT');
    form.append('enhancedCompression', 'true');

    let response = await fetch(`${BASE_URL}/obfuscate`, {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${API_KEY}`,
        ...form.getHeaders() 
      },
      body: form,
    });

    if (!response.ok) throw new Error('Obfuscation failed');
    const job = await response.json();

    // Poll for completion
    let jobStatus;
    for (let i = 0; i < 30; i++) {
      response = await fetch(`${BASE_URL}/jobs/${job.id}`, {
        headers: { 'Authorization': `Bearer ${API_KEY}` }
      });
      jobStatus = await response.json();
      
      if (jobStatus.status === 'completed') break;
      if (jobStatus.status === 'failed') throw new Error('Job failed');
      
      await new Promise(r => setTimeout(r, 2000));
    }

    // Download obfuscated code
    response = await fetch(`${BASE_URL}/jobs/${job.id}/download`, {
      headers: { 'Authorization': `Bearer ${API_KEY}` }
    });
    
    const obfuscatedCode = await response.text();

    // 2. Send to Luaguard Vercel
    console.log('Sending to Luaguard...');
    
    await fetch(LUAGUARD_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: obfuscatedCode })
    });

    console.log('Done! Obfuscated code sent to Luaguard');

  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Run it
const filePath = process.argv[2];
if (!filePath) {
  console.log('Usage: node script.js <file.lua>');
  process.exit(1);
}

obfuscateAndSend(filePath);
