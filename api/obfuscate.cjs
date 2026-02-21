const fs = require('fs');
const FormData = require('form-data');

const API_KEY = 'wynf_ew84z6L93odfnAc017sZaJdOVTwPBvH0';
const WYNFUSCATE_URL = 'https://wynfuscate.com/api/v1';
const LUAGUARD_URL = 'https://luaguard-ochre.vercel.app/api/start.cjs';

async function obfuscateAndSend(filePath) {
  try {
    // 1. Obfuscate using Wynfuscator
    console.log('📤 Obfuscating with Wynfuscator...');
    
    const form = new FormData();
    form.append('file', fs.createReadStream(filePath));
    form.append('targetPlatform', 'ROBLOX_COMPAT');
    form.append('enhancedCompression', 'true');

    let response = await fetch(`${WYNFUSCATE_URL}/obfuscate`, {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${API_KEY}`,
        ...form.getHeaders() 
      },
      body: form,
    });

    if (!response.ok) throw new Error('Obfuscation failed');
    const job = await response.json();
    console.log(`Job ID: ${job.id}`);

    // Poll for completion
    let jobStatus;
    for (let i = 0; i < 30; i++) {
      response = await fetch(`${WYNFUSCATE_URL}/jobs/${job.id}`, {
        headers: { 'Authorization': `Bearer ${API_KEY}` }
      });
      jobStatus = await response.json();
      
      if (jobStatus.status === 'completed') break;
      if (jobStatus.status === 'failed') throw new Error('Job failed');
      
      console.log('⏳ Waiting for obfuscation...');
      await new Promise(r => setTimeout(r, 2000));
    }

    // Download obfuscated code
    console.log('📥 Downloading obfuscated code...');
    response = await fetch(`${WYNFUSCATE_URL}/jobs/${job.id}/download`, {
      headers: { 'Authorization': `Bearer ${API_KEY}` }
    });
    
    const obfuscatedCode = await response.text();

    // 2. Send to Luaguard Vercel
    console.log('📤 Sending to Luaguard...');
    
    const luaguardResponse = await fetch(LUAGUARD_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: obfuscatedCode })
    });

    const result = await luaguardResponse.json();
    
    if (result.success) {
      console.log('✅ Success!');
      console.log('🔗 Paste URL:', result.pasteUrl);
    } else {
      console.log('❌ Failed:', result.error);
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Run it
const filePath = process.argv[2];
if (!filePath) {
  console.log('Usage: node obfuscate.js <file.lua>');
  process.exit(1);
}

obfuscateAndSend(filePath);
