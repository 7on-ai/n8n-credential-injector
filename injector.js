// N8N Credential Injector Service for Northflank (Flag-Based with N8N API)
// This runs as a ManualJob and processes all credentials with injection_requested = true

import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

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

console.log('🚀 N8N Credential Injector started (Flag-Based with N8N API):', {
  timestamp: new Date().toISOString(),
  n8nUrl: CONFIG.N8N_URL,
  hasSupabaseConfig: !!(CONFIG.SUPABASE_URL && CONFIG.SUPABASE_SERVICE_KEY),
  hasN8NConfig: !!(CONFIG.N8N_URL && CONFIG.N8N_ENCRYPTION_KEY),
  hasGoogleOAuth: !!(CONFIG.GOOGLE_OAUTH_CLIENT_ID && CONFIG.GOOGLE_OAUTH_CLIENT_SECRET),
  method: 'n8n_api_flag_based'
});

// Main execution function
async function main() {
  try {
    // Validate required environment variables
    if (!CONFIG.SUPABASE_URL || !CONFIG.SUPABASE_SERVICE_KEY) {
      throw new Error('Missing Supabase configuration');
    }

    if (!CONFIG.N8N_URL || !CONFIG.N8N_USER_EMAIL || !CONFIG.N8N_USER_PASSWORD) {
      throw new Error('Missing N8N configuration');
    }

    console.log('📥 Processing credentials with injection_requested = true...');

    // Initialize Supabase client
    const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_KEY);

    // Fetch all credentials pending injection
    const pendingCredentials = await fetchPendingCredentials(supabase);
    
    if (!pendingCredentials || pendingCredentials.length === 0) {
      console.log('ℹ️ No credentials pending injection found');
      process.exit(0);
    }

    console.log(`✅ Found ${pendingCredentials.length} credentials pending injection:`, 
      pendingCredentials.map(c => ({
        userId: c.user_id,
        provider: c.provider,
        tokenSource: c.token_source
      }))
    );

    // Authenticate with N8N API
    console.log('🔐 Authenticating with N8N API...');
    const authToken = await authenticateN8N();
    console.log('✅ N8N authentication successful');

    let totalSuccess = 0;
    let totalErrors = 0;

    // Process each credential
    for (const credData of pendingCredentials) {
      try {
        console.log(`🔄 Processing ${credData.provider} credential for user ${credData.user_id}...`);

        // Create credential payload
        const credentialPayload = createCredentialPayload(credData);

        console.log('📝 Generated credential payload:', {
          name: credentialPayload.name,
          type: credentialPayload.type,
          provider: credData.provider
        });

        // Create credential via N8N API
        const importResult = await createN8NCredential(authToken, credentialPayload);

        if (importResult.success) {
          // Update database with success status
          await updateCredentialStatus(
            supabase,
            credData.user_id,
            credData.provider,
            credData.token_source,
            true,
            importResult.credentialId,
            'Credentials injected successfully via N8N API (flag-based)',
            importResult.details
          );

          console.log('✅ Credential injection completed successfully:', {
            userId: credData.user_id,
            provider: credData.provider,
            credentialId: importResult.credentialId,
            method: 'northflank_n8n_api_flag_based'
          });

          totalSuccess++;
        } else {
          throw new Error(importResult.message || 'API request failed');
        }

      } catch (error) {
        console.error(`❌ Failed to inject credential for user ${credData.user_id}, provider ${credData.provider}:`, error);
        
        // Update database with error status
        try {
          await updateCredentialStatus(
            supabase,
            credData.user_id,
            credData.provider,
            credData.token_source,
            false,
            null,
            error.message,
            { 
              error_type: 'northflank_job_error_flag_based_api',
              timestamp: new Date().toISOString(),
              provider: credData.provider
            }
          );
          totalErrors++;
        } catch (dbError) {
          console.error('❌ Failed to update database with error:', dbError);
        }
      }
    }

    console.log('📊 Injection Summary:', {
      totalProcessed: pendingCredentials.length,
      successful: totalSuccess,
      errors: totalErrors,
      timestamp: new Date().toISOString()
    });

    if (totalErrors > 0) {
      console.log(`⚠️ ${totalErrors} credentials failed injection - check individual error logs`);
    }

    process.exit(totalErrors > 0 ? 1 : 0);

  } catch (error) {
    console.error('💥 Fatal error in credential injection:', error);
    process.exit(1);
  }
}

// Fetch credentials pending injection
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

    // Validate each credential
    const validCredentials = [];
    for (const row of data) {
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
        injection_requested_at: row.injection_requested_at
      });
    }

    console.log(`✅ Validated ${validCredentials.length} credential(s) for processing`);
    return validCredentials;

  } catch (error) {
    console.error('Error fetching pending credentials:', error);
    throw error;
  }
}

// Authenticate with N8N API
async function authenticateN8N() {
  try {
    const loginUrl = `${CONFIG.N8N_URL}/api/v1/login`;
    
    console.log('🔐 Attempting N8N login:', {
      url: loginUrl,
      email: CONFIG.N8N_USER_EMAIL
    });

    const response = await fetch(loginUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        email: CONFIG.N8N_USER_EMAIL,
        password: CONFIG.N8N_USER_PASSWORD
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`N8N authentication failed: ${response.status} - ${errorText}`);
    }

    const authData = await response.json();
    
    if (!authData.data || !authData.data.token) {
      throw new Error('No authentication token received from N8N');
    }

    console.log('✅ Authentication token received');
    return authData.data.token;

  } catch (error) {
    console.error('❌ N8N authentication error:', error);
    throw new Error(`Failed to authenticate with N8N: ${error.message}`);
  }
}

// Create credential payload for N8N API
function createCredentialPayload(credData) {
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

// Create credential via N8N API
async function createN8NCredential(authToken, credentialData) {
  try {
    const createUrl = `${CONFIG.N8N_URL}/api/v1/credentials`;
    
    console.log('📡 Creating credential via N8N API:', {
      url: createUrl,
      type: credentialData.type,
      name: credentialData.name
    });

    const response = await fetch(createUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Cookie': `n8n-auth=${authToken}`
      },
      body: JSON.stringify(credentialData)
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ N8N API error response:', {
        status: response.status,
        statusText: response.statusText,
        body: errorText
      });
      throw new Error(`N8N API request failed: ${response.status} - ${errorText}`);
    }

    const result = await response.json();
    
    console.log('✅ N8N API response:', {
      hasData: !!result.data,
      credentialId: result.data?.id
    });

    if (!result.data || !result.data.id) {
      throw new Error('No credential ID returned from N8N API');
    }

    return {
      success: true,
      credentialId: result.data.id,
      message: 'Credential created successfully via N8N API',
      details: {
        method: 'n8n_api_direct_flag_based',
        credentialName: result.data.name,
        credentialType: result.data.type,
        timestamp: new Date().toISOString()
      }
    };

  } catch (error) {
    console.error('❌ N8N API request failed:', error);
    return {
      success: false,
      message: error.message || 'N8N API request failed',
      details: {
        error_type: 'api_request_error',
        timestamp: new Date().toISOString()
      }
    };
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
        injection_method: 'northflank_n8n_api_flag_based',
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
