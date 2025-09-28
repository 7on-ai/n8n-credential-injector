// N8N Credential Injector Service for Northflank - Database Queue Approach
// This runs as a ManualJob that processes pending credential injections

import { createClient } from '@supabase/supabase-js';
import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import crypto from 'crypto';

const execAsync = promisify(exec);

// Configuration from environment variables (only fixed values from template)
const CONFIG = {
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
  N8N_URL: process.env.N8N_URL,
  N8N_USER_EMAIL: process.env.N8N_USER_EMAIL,
  N8N_USER_PASSWORD: process.env.N8N_USER_PASSWORD,
  N8N_ENCRYPTION_KEY: process.env.N8N_ENCRYPTION_KEY,
  USER_ID: process.env.USER_ID, // From template
  GOOGLE_OAUTH_CLIENT_ID: process.env.GOOGLE_OAUTH_CLIENT_ID,
  GOOGLE_OAUTH_CLIENT_SECRET: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
  NORTHFLANK_PROJECT_ID: process.env.NORTHFLANK_PROJECT_ID
};

console.log('🚀 N8N Credential Injector started:', {
  timestamp: new Date().toISOString(),
  templateUserId: CONFIG.USER_ID,
  n8nUrl: CONFIG.N8N_URL,
  projectId: CONFIG.NORTHFLANK_PROJECT_ID,
  hasSupabaseConfig: !!(CONFIG.SUPABASE_URL && CONFIG.SUPABASE_SERVICE_KEY),
  hasN8NConfig: !!(CONFIG.N8N_URL && CONFIG.N8N_ENCRYPTION_KEY),
  hasGoogleOAuth: !!(CONFIG.GOOGLE_OAUTH_CLIENT_ID && CONFIG.GOOGLE_OAUTH_CLIENT_SECRET)
});

// Main execution function
async function main() {
  try {
    if (!CONFIG.SUPABASE_URL || !CONFIG.SUPABASE_SERVICE_KEY) {
      throw new Error('Missing Supabase configuration');
    }

    if (!CONFIG.N8N_URL || !CONFIG.N8N_ENCRYPTION_KEY) {
      throw new Error('Missing N8N configuration');
    }

    if (!CONFIG.USER_ID) {
      throw new Error('Missing USER_ID from template');
    }

    console.log('📥 Processing pending credential injections for user:', CONFIG.USER_ID);

    // Initialize Supabase client
    const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_KEY);

    // Find pending credential injections for this user
    const pendingCredentials = await findPendingCredentials(supabase, CONFIG.USER_ID);
    
    if (!pendingCredentials || pendingCredentials.length === 0) {
      console.log('ℹ️ No pending credential injections found for this user');
      process.exit(0);
    }

    console.log(`📋 Found ${pendingCredentials.length} pending credential injections:`, 
      pendingCredentials.map(c => ({ provider: c.provider, created_at: c.created_at }))
    );

    // Verify n8n CLI is available
    try {
      const { stdout } = await execAsync('n8n --version', { timeout: 10000 });
      console.log('✅ N8N CLI available:', stdout.trim());
    } catch (error) {
      throw new Error(`N8N CLI not available: ${error.message}`);
    }

    let successCount = 0;
    let failureCount = 0;

    // Process each pending credential
    for (const credentialRecord of pendingCredentials) {
      try {
        console.log(`\n🔄 Processing ${credentialRecord.provider} credential...`);
        
        // Create credential template
        const credentialTemplate = createCredentialTemplate(credentialRecord);
        const jsonContent = generateCredentialJSON([credentialTemplate]);

        console.log('📝 Generated credential template:', {
          id: credentialTemplate.id,
          name: credentialTemplate.name,
          type: credentialTemplate.type,
          provider: credentialRecord.provider
        });

        // Execute n8n CLI import
        const importResult = await executeN8NImport(jsonContent, credentialRecord);

        if (importResult.success) {
          // Update database with success status
          await updateCredentialStatus(
            supabase,
            CONFIG.USER_ID,
            credentialRecord.provider,
            credentialRecord.token_source || 'auth0',
            true,
            importResult.credentialId,
            'Credentials injected successfully via Northflank job',
            importResult.details
          );

          console.log(`✅ ${credentialRecord.provider} credential injection completed successfully`);
          successCount++;
        } else {
          throw new Error(importResult.message || 'Import failed');
        }

      } catch (error) {
        console.error(`❌ Failed to process ${credentialRecord.provider} credential:`, error);
        
        // Update database with error status
        await updateCredentialStatus(
          supabase,
          CONFIG.USER_ID,
          credentialRecord.provider,
          credentialRecord.token_source || 'auth0',
          false,
          null,
          error.message,
          { error_type: 'northflank_job_processing_error' }
        );
        
        failureCount++;
      }
    }

    console.log(`\n📊 Processing completed:`, {
      total: pendingCredentials.length,
      successful: successCount,
      failed: failureCount
    });

    if (successCount > 0) {
      console.log('✅ Some credentials were successfully injected');
    }

    if (failureCount > 0) {
      console.log('⚠️ Some credentials failed to inject');
      process.exit(1);
    } else {
      process.exit(0);
    }

  } catch (error) {
    console.error('❌ Credential injection failed:', error);
    process.exit(1);
  }
}

// Find pending credential injections for user
async function findPendingCredentials(supabase, userId) {
  try {
    const { data, error } = await supabase
      .from('user_social_credentials')
      .select('*')
      .eq('user_id', userId)
      .eq('injected_to_n8n', false)
      .is('injection_error', null)  // Only get ones that haven't failed yet
      .order('created_at', { ascending: true });

    if (error) {
      console.error('Database query error:', error);
      return null;
    }

    return data || [];
  } catch (error) {
    console.error('Error finding pending credentials:', error);
    return null;
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

  return {
    id: credentialId,
    name: `${credData.provider.charAt(0).toUpperCase() + credData.provider.slice(1)} OAuth2 - ${timestamp}`,
    type: credentialType,
    data: {
      clientId: credData.client_id,
      clientSecret: credData.client_secret,
      accessToken: credData.access_token,
      refreshToken: credData.refresh_token || '',
      tokenType: 'Bearer',
      grantType: 'authorizationCode'
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

// Generate n8n import JSON
function generateCredentialJSON(credentials) {
  return JSON.stringify({
    version: "1.0.0",
    credentials: credentials,
    workflows: []
  }, null, 2);
}

// Execute n8n CLI import
async function executeN8NImport(jsonContent, credData) {
  const tempFileName = `credentials-${Date.now()}.json`;
  const tempFilePath = `/tmp/${tempFileName}`;

  try {
    console.log('📝 Writing credential file...');
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
      const credentialId = JSON.parse(jsonContent).credentials[0].id;
      
      return {
        success: true,
        credentialId: credentialId,
        message: 'Credentials imported successfully via N8N CLI',
        details: {
          method: 'northflank_n8n_cli_queue',
          output: stdout.substring(0, 500), // Limit output size
          provider: credData.provider,
          tokenSource: credData.token_source
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
        timestamp: new Date().toISOString()
      }
    };
  } finally {
    // Cleanup temporary file
    try {
      await fs.unlink(tempFilePath);
      console.log('🧹 Cleaned up temporary file');
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
      additional_data: JSON.stringify({
        injection_method: 'northflank_n8n_cli_queue',
        success: success,
        error: success ? null : message,
        details: details || {},
        timestamp: new Date().toISOString(),
        platform: 'northflank',
        version: '3.1'
      }),
      updated_at: new Date().toISOString()
    };

    if (credentialId) {
      updateData.n8n_credential_id = credentialId;
      updateData.n8n_credential_ids = JSON.stringify([credentialId]);
    }

    // Use token_source in the where clause to match unique constraint
    let whereClause = supabase
      .from('user_social_credentials')
      .update(updateData)
      .eq('user_id', userId)
      .eq('provider', provider);
      
    if (tokenSource) {
      whereClause = whereClause.eq('token_source', tokenSource);
    }

    const { error } = await whereClause;

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
