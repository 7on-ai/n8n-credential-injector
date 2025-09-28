// N8N Credential Injector Service for Northflank (Database Flag Based)
// This runs as a ManualJob and processes all credentials with injection_requested=true

import { createClient } from '@supabase/supabase-js';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

const execAsync = promisify(exec);

// Configuration from environment variables
const CONFIG = {
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
  N8N_URL: process.env.N8N_URL,
  N8N_USER_EMAIL: process.env.N8N_USER_EMAIL,
  N8N_USER_PASSWORD: process.env.N8N_USER_PASSWORD,
  N8N_ENCRYPTION_KEY: process.env.N8N_ENCRYPTION_KEY,
  GOOGLE_OAUTH_CLIENT_ID: process.env.GOOGLE_OAUTH_CLIENT_ID,
  GOOGLE_OAUTH_CLIENT_SECRET: process.env.GOOGLE_OAUTH_CLIENT_SECRET
};

console.log('🚀 N8N Credential Injector started (Database Flag Based):', {
  timestamp: new Date().toISOString(),
  n8nUrl: CONFIG.N8N_URL,
  hasSupabaseConfig: !!(CONFIG.SUPABASE_URL && CONFIG.SUPABASE_SERVICE_KEY),
  hasN8NConfig: !!(CONFIG.N8N_URL && CONFIG.N8N_ENCRYPTION_KEY),
  hasGoogleOAuth: !!(CONFIG.GOOGLE_OAUTH_CLIENT_ID && CONFIG.GOOGLE_OAUTH_CLIENT_SECRET),
  method: 'database_flag_based'
});

// Main execution function
async function main() {
  try {
    console.log('🔍 Environment variables check:', {
      N8N_ENCRYPTION_KEY: CONFIG.N8N_ENCRYPTION_KEY ? 'SET' : 'MISSING',
      SUPABASE_URL: CONFIG.SUPABASE_URL ? 'SET' : 'MISSING',
      SUPABASE_SERVICE_KEY: CONFIG.SUPABASE_SERVICE_KEY ? 'SET' : 'MISSING',
      method: 'flag_based_processing'
    });

    if (!CONFIG.SUPABASE_URL || !CONFIG.SUPABASE_SERVICE_KEY) {
      throw new Error('Missing Supabase configuration');
    }

    if (!CONFIG.N8N_URL || !CONFIG.N8N_ENCRYPTION_KEY) {
      throw new Error('Missing N8N configuration');
    }

    console.log('📥 Processing ALL credentials with injection_requested=true flag');

    // Initialize Supabase client
    const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_KEY);

    // Fetch ALL pending credentials from database
    const pendingCredentials = await fetchPendingCredentials(supabase);
    
    if (!pendingCredentials || pendingCredentials.length === 0) {
      console.log('ℹ️ No pending credentials found for injection');
      process.exit(0);
    }

    console.log(`✅ Found ${pendingCredentials.length} pending credential(s) for injection:`, 
      pendingCredentials.map(c => ({
        user_id: c.user_id,
        provider: c.provider,
        token_source: c.token_source,
        requested_at: c.injection_requested_at
      }))
    );

    // Verify n8n CLI is available
    try {
      const { stdout } = await execAsync('n8n --version', { timeout: 10000 });
      console.log('✅ N8N CLI available:', stdout.trim());
    } catch (error) {
      throw new Error(`N8N CLI not available: ${error.message}`);
    }

    // Process each credential
    let successCount = 0;
    let errorCount = 0;

    for (const credData of pendingCredentials) {
      try {
        console.log(`🔄 Processing credential for user: ${credData.user_id}, provider: ${credData.provider}`);
        
        // Create credential template
        const credentialTemplate = createCredentialTemplate(credData);
        const jsonContent = generateCredentialJSON([credentialTemplate]);

        console.log('📝 Generated credential template:', {
          id: credentialTemplate.id,
          name: credentialTemplate.name,
          type: credentialTemplate.type
        });

        // Execute n8n CLI import
        const importResult = await executeN8NImport(jsonContent, credData);

        if (importResult.success) {
          // Update database with success status
          await updateCredentialStatus(
            supabase,
            credData.user_id,
            credData.provider,
            credData.token_source,
            true,
            importResult.credentialId,
            'Credentials injected successfully via Northflank job (flag-based)',
            importResult.details
          );

          console.log('✅ Credential injection completed for:', {
            user_id: credData.user_id,
            provider:
