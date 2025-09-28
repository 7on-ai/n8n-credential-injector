// N8N Credential Injector Service for Northflank
// This runs as a ManualJob that gets triggered by Edge Functions via Northflank API

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
  USER_ID: process.env.USER_ID,
  PROVIDER: process.env.PROVIDER,
  GOOGLE_OAUTH_CLIENT_ID: process.env.GOOGLE_OAUTH_CLIENT_ID,
  GOOGLE_OAUTH_CLIENT_SECRET: process.env.GOOGLE_OAUTH_CLIENT_SECRET
};

console.log('🚀 N8N Credential Injector started:', {
  timestamp: new Date().toISOString(),
  userId: CONFIG.USER_ID,
  provider: CONFIG.PROVIDER,
  n8nUrl: CONFIG.N8N_URL,
  hasSupabaseConfig: !!(CONFIG.SUPABASE_URL && CONFIG.SUPABASE_SERVICE_KEY),
  hasN8NConfig: !!(CONFIG.N8N_URL && CONFIG.N8N_ENCRYPTION_KEY),
  hasGoogleOAuth: !!(CONFIG.GOOGLE_OAUTH_CLIENT_ID && CONFIG.GOOGLE_OAUTH_CLIENT_SECRET)
});

// Main execution function
async function main() {
  try {
    // Validate required environment variables
    if (!CONFIG.USER_ID || !CONFIG.PROVIDER) {
      throw new Error('Missing required parameters: USER_ID and PROVIDER must be set');
    }

    if (!CONFIG.SUPABASE_URL || !CONFIG.SUPABASE_SERVICE_KEY) {
      throw new Error('Missing Supabase configuration');
    }

    if (!CONFIG.N8N_URL || !CONFIG.N8N_ENCRYPTION_KEY) {
      throw new Error('Missing N8N configuration');
    }

    console.log(`📥 Processing credential injection for user: ${CONFIG.USER_ID}, provider: ${CONFIG.PROVIDER}`);

    // Initialize Supabase client
    const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_KEY);

    // Fetch user credentials from database
    const credData = await fetchUserCredentials(supabase, CONFIG.USER_ID, CONFIG.PROVIDER);
    if (!credData) {
      throw new Error('User credentials not found in database');
    }

    console.log('✅ Credentials fetched from database:', {
      provider: credData.provider,
      hasAccessToken: !!credData.access_token,
      hasRefreshToken: !!credData.refresh_token,
      hasClientCredentials: !!(credData.client_id && credData.client_secret),
      tokenSource: credData.token_source
    });

    // Verify n8n CLI is available
    try {
      const { stdout } = await execAsync('n8n --version', { timeout: 10000 });
      console.log('✅ N8N CLI available:', stdout.trim());
    } catch (error) {
      throw new Error(`N8N CLI not available: ${error.message}`);
    }

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
        CONFIG.USER_ID,
        CONFIG.PROVIDER,
        true,
        importResult.credentialId,
        'Credentials injected successfully via Northflank job',
        importResult.details
      );

      console.log('✅ Credential injection completed successfully:', {
        credentialId: importResult.credentialId,
        method: 'northflank_n8n_cli'
      });

      process.exit(0);
    } else {
      throw new Error(importResult.message || 'Import failed');
    }

  } catch (error) {
    console.error('❌ Credential injection failed:', error);
    
    // Update database with error status
    if (CONFIG.SUPABASE_URL && CONFIG.SUPABASE_SERVICE_KEY && CONFIG.USER_ID && CONFIG.PROVIDER) {
      try {
        const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_KEY);
        await updateCredentialStatus(
          supabase,
          CONFIG.USER_ID,
          CONFIG.PROVIDER,
          false,
          null,
          error.message,
          { error_type: 'northflank_job_error', timestamp: new Date().toISOString() }
        );
      } catch (dbError) {
        console.error('❌ Failed to update database with error:', dbError);
      }
    }

    process.exit(1);
  }
}

// Fetch user credentials from Supabase
async function fetchUserCredentials(supabase, userId, provider) {
  try {
    const { data, error } = await supabase
      .from('user_social_credentials')
      .select('*')
      .eq('user_id', userId)
      .eq('provider', provider)
      .single();

    if (error) {
      console.error('Database query error:', error);
      return null;
    }

    if (!data) {
      console.error('No credentials found for user and provider');
      return null;
    }

    // Validate required fields
    if (!data.access_token || !data.client_id || !data.client_secret) {
      console.error('Incomplete credential data:', {
        hasAccessToken: !!data.access_token,
        hasClientId: !!data.client_id,
        hasClientSecret: !!data.client_secret
      });
      return null;
    }

    return {
      user_id: userId,
      provider: provider,
      access_token: data.access_token,
      refresh_token: data.refresh_token || '',
      client_id: data.client_id,
      client_secret: data.client_secret,
      token_source: data.token_source,
      n8n_encryption_key: CONFIG.N8N_ENCRYPTION_KEY
    };

  } catch (error) {
    console.error('Error fetching credentials:', error);
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
      refreshToken: credData.refresh_token,
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
          method: 'northflank_n8n_cli',
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
async function updateCredentialStatus(supabase, userId, provider, success, credentialId, message, details) {
  try {
    const updateData = {
      injected_to_n8n: success,
      injected_at: success ? new Date().toISOString() : null,
      injection_error: success ? null : message,
      injection_attempted_at: new Date().toISOString(),
      additional_data: JSON.stringify({
        injection_method: 'northflank_n8n_cli',
        success: success,
        error: success ? null : message,
        details: details || {},
        timestamp: new Date().toISOString(),
        platform: 'northflank',
        version: '3.0'
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
      .eq('provider', provider);

    if (error) {
      console.error('❌ Database update failed:', error);
      throw new Error(`Database update failed: ${error.message}`);
    }

    console.log('✅ Database updated successfully:', {
      userId,
      provider,
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
