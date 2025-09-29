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
        
        // Generate JSON in CORRECT N8N CLI format (array of credentials)
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
            provider: credData.provider,
            credentialId: importResult.credentialId,
            method: 'flag_based_northflank_cli'
          });

          successCount++;
        } else {
          throw new Error(importResult.message || 'Import failed');
        }

      } catch (error) {
        console.error(`❌ Failed to process credential for ${credData.user_id}/${credData.provider}:`, error);
        
        // Update database with error status
        await updateCredentialStatus(
          supabase,
          credData.user_id,
          credData.provider,
          credData.token_source,
          false,
          null,
          error.message,
          { error_type: 'processing_error', timestamp: new Date().toISOString() }
        );

        errorCount++;
      }
    }

    console.log('🎯 Batch processing completed:', {
      total: pendingCredentials.length,
      success: successCount,
      errors: errorCount,
      method: 'flag_based_processing'
    });

    if (errorCount === 0) {
      console.log('✅ All credentials processed successfully');
      process.exit(0);
    } else {
      console.log(`⚠️ Completed with ${errorCount} error(s)`);
      process.exit(0); // Don't fail the job if some credentials succeeded
    }

  } catch (error) {
    console.error('❌ Credential injection batch failed:', error);
    process.exit(1);
  }
}

// Fetch ALL pending credentials from database
async function fetchPendingCredentials(supabase) {
  try {
    console.log('🔍 Querying database for pending injection requests...');
    
    const { data, error } = await supabase
      .from('user_social_credentials')
      .select('*')
      .eq('injection_requested', true)
      .eq('injected_to_n8n', false)
      .order('injection_requested_at', { ascending: true });

    if (error) {
      console.error('Database query error:', error);
      throw new Error(`Database query failed: ${error.message}`);
    }

    console.log(`📊 Query result: Found ${data?.length || 0} pending credential(s)`);

    if (!data || data.length === 0) {
      return [];
    }

    // Process and validate each credential
    const validCredentials = [];
    for (const row of data) {
      // Validate required fields
      if (!row.access_token || !row.client_id || !row.client_secret) {
        console.warn(`⚠️ Skipping incomplete credential: ${row.user_id}/${row.provider}`, {
          hasAccessToken: !!row.access_token,
          hasClientId: !!row.client_id,
          hasClientSecret: !!row.client_secret
        });
        continue;
      }

      validCredentials.push({
        user_id: row.user_id,
        provider: row.provider,
        token_source: row.token_source || 'auth0',
        access_token: row.access_token,
        refresh_token: row.refresh_token || '',
        client_id: row.client_id,
        client_secret: row.client_secret,
        injection_requested_at: row.injection_requested_at,
        n8n_encryption_key: CONFIG.N8N_ENCRYPTION_KEY
      });
    }

    console.log(`✅ Validated ${validCredentials.length} credential(s) for processing`);
    return validCredentials;

  } catch (error) {
    console.error('Error fetching pending credentials:', error);
    throw error;
  }
}

// Create n8n credential template
function createCredentialTemplate(credData) {
  const credentialId = crypto.randomUUID();
  const timestamp = new Date().toISOString().slice(0, 16).replace('T', ' ');

  const credentialTypes = {
    google: 'googleOAuth2Api',
    spotify: 'spotifyOAuth2Api',
    github: 'githubOAuth2Api',
    discord: 'discordOAuth2Api',
    linkedin: 'linkedInOAuth2Api'
  };

  const credentialType = credentialTypes[credData.provider];
  if (!credentialType) {
    throw new Error(`Unsupported provider: ${credData.provider}`);
  }

  // FIXED: Return structure that matches N8N CLI export format
  return {
    id: credentialId,
    name: `${credData.provider.charAt(0).toUpperCase() + credData.provider.slice(1)} OAuth2 - ${timestamp}`,
    type: credentialType,
    data: {
      clientId: credData.client_id,
      clientSecret: credData.client_secret,
      accessToken: credData.access_token,
      refreshToken: credData.refresh_token,
      tokenType: 'Bearer',
      grantType: 'authorizationCode'
    }
  };
}

// FIXED: Generate n8n import JSON - now returns ARRAY format directly
function generateCredentialJSON(credentials) {
  // N8N CLI expects credentials as a direct array, not wrapped in an object
  return JSON.stringify(credentials, null, 2);
}

// Execute n8n CLI import
async function executeN8NImport(jsonContent, credData) {
  const tempFileName = `credentials-${Date.now()}-${credData.user_id.slice(0, 8)}.json`;
  const tempFilePath = `/tmp/${tempFileName}`;

  try {
    console.log('📝 Writing credential file:', tempFileName);
    console.log('📄 JSON content preview:', jsonContent.substring(0, 300) + '...');
    
    await fs.writeFile(tempFilePath, jsonContent);

    // Set up environment for n8n CLI
    const env = {
      ...process.env,
      N8N_ENCRYPTION_KEY: CONFIG.N8N_ENCRYPTION_KEY,
      N8N_DATABASE_TYPE: 'postgresdb',
      DB_TYPE: 'postgresdb',
      DB_POSTGRESDB_HOST: process.env.DB_POSTGRESDB_HOST,
      DB_POSTGRESDB_PORT: process.env.DB_POSTGRESDB_PORT,
      DB_POSTGRESDB_DATABASE: process.env.DB_POSTGRESDB_DATABASE,
      DB_POSTGRESDB_USER: process.env.DB_POSTGRESDB_USER,
      DB_POSTGRESDB_PASSWORD: process.env.DB_POSTGRESDB_PASSWORD,
      N8N_LOG_LEVEL: 'error',
      N8N_USER_MANAGEMENT_DISABLED: 'true'
    };

    console.log('🔧 Environment configured:', {
      hasEncryptionKey: !!env.N8N_ENCRYPTION_KEY,
      hasDbConfig: !!(env.DB_POSTGRESDB_HOST && env.DB_POSTGRESDB_PASSWORD),
      dbType: env.N8N_DATABASE_TYPE
    });

    // Execute n8n import command
    const command = `n8n import:credentials --input=${tempFilePath}`;
    console.log(`🚀 Executing: ${command}`);

    const { stdout, stderr } = await execAsync(command, {
      env,
      timeout: 120000, // 2 minutes timeout
      cwd: '/tmp'
    });

    console.log('📤 N8N CLI output:', stdout);
    if (stderr) {
      console.log('⚠️ N8N CLI stderr:', stderr);
    }

    // Check for success indicators
    const successIndicators = [
      'Successfully imported',
      'imported',
      'credential',
      'Saved credential'
    ];

    const isSuccess = successIndicators.some(indicator => 
      stdout.toLowerCase().includes(indicator.toLowerCase())
    );

    if (isSuccess) {
      const credentialId = JSON.parse(jsonContent)[0].id;
      
      return {
        success: true,
        credentialId: credentialId,
        message: 'Credentials imported successfully via N8N CLI (flag-based)',
        details: {
          method: 'flag_based_northflank_n8n_cli',
          output: stdout.substring(0, 500), // Limit output size
          provider: credData.provider,
          tokenSource: credData.token_source,
          user_id: credData.user_id
        }
      };
    } else {
      throw new Error(`Import failed - no success indicators found in output: ${stdout}`);
    }

  } catch (error) {
    console.error('❌ N8N CLI execution failed:', error);
    return {
      success: false,
      message: error.message || 'N8N CLI execution failed',
      details: {
        error_type: 'cli_execution_error',
        timestamp: new Date().toISOString(),
        user_id: credData.user_id,
        provider: credData.provider
      }
    };
  } finally {
    // Cleanup temporary file
    try {
      await fs.unlink(tempFilePath);
      console.log('🧹 Cleaned up temporary file:', tempFileName);
    } catch (cleanupError) {
      console.warn('⚠️ Failed to cleanup temporary file:', cleanupError.message);
    }
  }
}

// Update credential status in database
async function updateCredentialStatus(supabase, userId, provider, tokenSource, success, credentialId, message, details) {
  try {
    const updateData = {
      injected_to_n8n: success,
      injected_at: success ? new Date().toISOString() : null,
      injection_error: success ? null : message,
      injection_attempted_at: new Date().toISOString(),
      injection_requested: false, // Reset flag after processing
      additional_data: JSON.stringify({
        injection_method: 'flag_based_northflank_n8n_cli',
        success: success,
        error: success ? null : message,
        details: details || {},
        timestamp: new Date().toISOString(),
        platform: 'northflank',
        version: '4.0'
      }),
      updated_at: new Date().toISOString()
    };

    if (credentialId) {
      updateData.n8n_credential_id = credentialId;
      updateData.n8n_credential_ids = JSON.stringify([credentialId]);
    }

    const { error } = await supabase
      .from('user_social_credentials')
      .update(updateData)
      .eq('user_id', userId)
      .eq('provider', provider)
      .eq('token_source', tokenSource);

    if (error) {
      console.error('❌ Database update failed:', error);
      throw new Error(`Database update failed: ${error.message}`);
    }

    console.log('✅ Database updated successfully:', {
      userId,
      provider,
      tokenSource,
      success,
      credentialId
    });

  } catch (error) {
    console.error('❌ Failed to update credential status:', error);
    throw error;
  }
}

// Run main function
main().catch(error => {
  console.error('💥 Fatal error:', error);
  process.exit(1);
});
