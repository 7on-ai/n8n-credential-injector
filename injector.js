// N8N Credential Injector with Built-in Diagnostics
// Step 1: Check database schema
// Step 2: If schema is correct, inject credentials automatically

import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import pg from 'pg';
const { Client } = pg;

// Configuration from environment variables
const CONFIG = {
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVICE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,
  N8N_URL: process.env.N8N_URL,
  N8N_ENCRYPTION_KEY: process.env.N8N_ENCRYPTION_KEY,
  GOOGLE_OAUTH_CLIENT_ID: process.env.GOOGLE_OAUTH_CLIENT_ID,
  GOOGLE_OAUTH_CLIENT_SECRET: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
  DB_POSTGRESDB_HOST: process.env.DB_POSTGRESDB_HOST,
  DB_POSTGRESDB_PORT: process.env.DB_POSTGRESDB_PORT || '5432',
  DB_POSTGRESDB_DATABASE: process.env.DB_POSTGRESDB_DATABASE,
  DB_POSTGRESDB_USER: process.env.DB_POSTGRESDB_USER,
  DB_POSTGRESDB_PASSWORD: process.env.DB_POSTGRESDB_PASSWORD
};

console.log('🚀 N8N Credential Injector started:', {
  timestamp: new Date().toISOString(),
  mode: 'DIAGNOSTIC + AUTO INJECT',
  hasSupabaseConfig: !!(CONFIG.SUPABASE_URL && CONFIG.SUPABASE_SERVICE_KEY),
  hasN8NConfig: !!(CONFIG.N8N_URL && CONFIG.N8N_ENCRYPTION_KEY),
  hasN8NDb: !!(CONFIG.DB_POSTGRESDB_HOST && CONFIG.DB_POSTGRESDB_PASSWORD)
});

// N8N Encryption class
class N8NCrypto {
  constructor(encryptionKey) {
    this.encryptionKey = encryptionKey;
  }

  encrypt(data) {
    const algorithm = 'aes-256-cbc';
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(this.encryptionKey).digest();
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    return iv.toString('hex') + ':' + encrypted;
  }
}

// Main execution
async function main() {
  let pgClient = null;
  
  try {
    console.log('\n========================================');
    console.log('STEP 1: ENVIRONMENT CHECK');
    console.log('========================================');
    
    validateEnvironment();

    console.log('\n========================================');
    console.log('STEP 2: DATABASE CONNECTION');
    console.log('========================================');
    
    pgClient = await connectToDatabase();

    console.log('\n========================================');
    console.log('STEP 3: DATABASE DIAGNOSTICS');
    console.log('========================================');
    
    const schemaValid = await runDiagnostics(pgClient);

    if (!schemaValid) {
      console.log('\n❌ Schema validation failed. Stopping here.');
      process.exit(1);
    }

    console.log('\n========================================');
    console.log('STEP 4: FETCH PENDING CREDENTIALS');
    console.log('========================================');
    
    const supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_SERVICE_KEY);
    const pendingCredentials = await fetchPendingCredentials(supabase);
    
    if (!pendingCredentials || pendingCredentials.length === 0) {
      console.log('ℹ️ No pending credentials found');
      process.exit(0);
    }

    console.log(`✅ Found ${pendingCredentials.length} pending credential(s)`);

    console.log('\n========================================');
    console.log('STEP 5: INJECT CREDENTIALS');
    console.log('========================================');
    
    const n8nCrypto = new N8NCrypto(CONFIG.N8N_ENCRYPTION_KEY);
    let successCount = 0;
    let errorCount = 0;

    for (const credData of pendingCredentials) {
      try {
        console.log(`\n🔄 Processing: ${credData.user_id}/${credData.provider}`);
        
        const result = await insertCredentialToDatabase(
          pgClient, 
          n8nCrypto, 
          credData
        );

        if (result.success) {
          await updateCredentialStatus(
            supabase,
            credData.user_id,
            credData.provider,
            credData.token_source,
            true,
            result.credentialId,
            'Credentials injected via direct database insert',
            result.details
          );

          console.log('✅ Success:', {
            credentialId: result.credentialId,
            name: result.details.credentialName
          });
          successCount++;
        } else {
          throw new Error(result.message || 'Insert failed');
        }

      } catch (error) {
        console.error(`❌ Failed: ${error.message}`);
        
        await updateCredentialStatus(
          supabase,
          credData.user_id,
          credData.provider,
          credData.token_source,
          false,
          null,
          error.message,
          { error_type: 'processing_error' }
        );
        errorCount++;
      }
    }

    console.log('\n========================================');
    console.log('STEP 6: SUMMARY');
    console.log('========================================');
    console.log({
      total: pendingCredentials.length,
      success: successCount,
      errors: errorCount
    });

    process.exit(errorCount === 0 ? 0 : 0);

  } catch (error) {
    console.error('\n❌ FATAL ERROR:', error.message);
    console.error(error.stack);
    process.exit(1);
  } finally {
    if (pgClient) {
      try {
        await pgClient.end();
        console.log('\n🔌 Database connection closed');
      } catch (err) {
        console.error('Error closing database:', err.message);
      }
    }
  }
}

// Validate environment variables
function validateEnvironment() {
  const required = [
    'SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'N8N_ENCRYPTION_KEY',
    'DB_POSTGRESDB_HOST',
    'DB_POSTGRESDB_PASSWORD',
    'DB_POSTGRESDB_DATABASE',
    'DB_POSTGRESDB_USER'
  ];

  const missing = required.filter(key => !CONFIG[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  console.log('✅ All required environment variables present');
  console.log('Database config:', {
    host: CONFIG.DB_POSTGRESDB_HOST,
    port: CONFIG.DB_POSTGRESDB_PORT,
    database: CONFIG.DB_POSTGRESDB_DATABASE,
    user: CONFIG.DB_POSTGRESDB_USER
  });
}

// Connect to N8N database
async function connectToDatabase() {
  const client = new Client({
    host: CONFIG.DB_POSTGRESDB_HOST,
    port: parseInt(CONFIG.DB_POSTGRESDB_PORT),
    database: CONFIG.DB_POSTGRESDB_DATABASE,
    user: CONFIG.DB_POSTGRESDB_USER,
    password: CONFIG.DB_POSTGRESDB_PASSWORD,
    ssl: false,
    connectionTimeoutMillis: 10000
  });

  console.log('🔌 Connecting to N8N PostgreSQL...');
  await client.connect();
  console.log('✅ Connected successfully');
  
  return client;
}

// Run database diagnostics
async function runDiagnostics(pgClient) {
  try {
    console.log('\n📊 Checking credentials_entity table schema...\n');

    // Check if table exists
    const tableCheck = await pgClient.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'credentials_entity'
      );
    `);

    if (!tableCheck.rows[0].exists) {
      console.error('❌ Table credentials_entity does not exist!');
      return false;
    }

    console.log('✅ Table credentials_entity exists');

    // Get table schema
    const schemaQuery = await pgClient.query(`
      SELECT 
        column_name, 
        data_type, 
        is_nullable,
        column_default,
        character_maximum_length
      FROM information_schema.columns
      WHERE table_name = 'credentials_entity'
      ORDER BY ordinal_position;
    `);

    console.log('\n📋 Table Schema:');
    console.log('─────────────────────────────────────────────────────');
    schemaQuery.rows.forEach(col => {
      console.log(`Column: ${col.column_name}`);
      console.log(`  Type: ${col.data_type}`);
      console.log(`  Nullable: ${col.is_nullable}`);
      console.log(`  Default: ${col.column_default || 'none'}`);
      if (col.character_maximum_length) {
        console.log(`  Max Length: ${col.character_maximum_length}`);
      }
      console.log('─────────────────────────────────────────────────────');
    });

    // Check for required columns
    const columnNames = schemaQuery.rows.map(r => r.column_name);
    const requiredColumns = ['id', 'name', 'type', 'data'];
    const missingColumns = requiredColumns.filter(col => !columnNames.includes(col));

    if (missingColumns.length > 0) {
      console.error(`❌ Missing required columns: ${missingColumns.join(', ')}`);
      return false;
    }

    console.log('\n✅ All required columns present:', requiredColumns.join(', '));

    // Get sample credential (if any exists)
    const sampleQuery = await pgClient.query(`
      SELECT id, name, type, "createdAt", "updatedAt"
      FROM credentials_entity
      LIMIT 1;
    `);

    if (sampleQuery.rows.length > 0) {
      console.log('\n📝 Sample credential (existing):');
      console.log(JSON.stringify(sampleQuery.rows[0], null, 2));
    } else {
      console.log('\nℹ️ No existing credentials in database');
    }

    // Count total credentials
    const countQuery = await pgClient.query(`
      SELECT COUNT(*) as total FROM credentials_entity;
    `);
    console.log(`\n📊 Total credentials in database: ${countQuery.rows[0].total}`);

    // Check for user relationship (if shared_credentials table exists)
    const sharedTableCheck = await pgClient.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'shared_credentials'
      );
    `);

    if (sharedTableCheck.rows[0].exists) {
      console.log('✅ shared_credentials table exists (may need user mapping)');
      
      // Get shared_credentials schema
      const sharedSchema = await pgClient.query(`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_name = 'shared_credentials'
        ORDER BY ordinal_position;
      `);
      
      console.log('\n📋 shared_credentials columns:', 
        sharedSchema.rows.map(r => r.column_name).join(', ')
      );
    } else {
      console.log('⚠️ shared_credentials table not found');
    }

    console.log('\n✅ DIAGNOSTICS PASSED - Ready to inject credentials');
    return true;

  } catch (error) {
    console.error('❌ Diagnostics failed:', error.message);
    console.error(error.stack);
    return false;
  }
}

// Fetch pending credentials from Supabase
async function fetchPendingCredentials(supabase) {
  const { data, error } = await supabase
    .from('user_social_credentials')
    .select('*')
    .eq('injection_requested', true)
    .eq('injected_to_n8n', false)
    .order('injection_requested_at', { ascending: true });

  if (error) throw new Error(`Supabase query failed: ${error.message}`);
  if (!data || data.length === 0) return [];

  const valid = [];
  for (const row of data) {
    if (!row.access_token || !row.client_id || !row.client_secret) {
      console.warn(`⚠️ Skipping incomplete: ${row.user_id}/${row.provider}`);
      continue;
    }

    valid.push({
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

  return valid;
}

// Insert credential into N8N database
async function insertCredentialToDatabase(pgClient, n8nCrypto, credData) {
  try {
    const timestamp = new Date();
    const credentialId = crypto.randomUUID();

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

    // Prepare credential data
    const credentialDataObject = {
      clientId: credData.client_id,
      clientSecret: credData.client_secret,
      accessToken: credData.access_token,
      refreshToken: credData.refresh_token,
      tokenType: 'Bearer',
      grantType: 'authorizationCode',
      oauthTokenData: {
        access_token: credData.access_token,
        refresh_token: credData.refresh_token,
        token_type: 'Bearer'
      }
    };

    console.log('  📦 Preparing credential data...');
    console.log('  🔐 Encrypting with N8N_ENCRYPTION_KEY...');

    const encryptedData = n8nCrypto.encrypt(credentialDataObject);

    const credentialName = `${credData.provider.charAt(0).toUpperCase() + credData.provider.slice(1)} OAuth2 - ${timestamp.toISOString().slice(0, 16).replace('T', ' ')}`;

    // Insert query
    const insertQuery = `
      INSERT INTO credentials_entity (
        id,
        name,
        type,
        data,
        "createdAt",
        "updatedAt"
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING id, name, type
    `;

    const values = [
      credentialId,
      credentialName,
      credentialType,
      encryptedData,
      timestamp,
      timestamp
    ];

    console.log('  💾 Inserting into database...');
    const result = await pgClient.query(insertQuery, values);

    if (result.rowCount > 0) {
      console.log('  ✅ Database insert successful');
      return {
        success: true,
        credentialId: credentialId,
        message: 'Credential inserted successfully',
        details: {
          method: 'direct_database_insert',
          credentialName: credentialName,
          credentialType: credentialType,
          timestamp: timestamp.toISOString()
        }
      };
    } else {
      throw new Error('No rows inserted');
    }

  } catch (error) {
    console.error('  ❌ Insert error:', error.message);
    return {
      success: false,
      message: error.message,
      details: {
        error_type: 'database_error',
        error_code: error.code
      }
    };
  }
}

// Update credential status in Supabase
async function updateCredentialStatus(supabase, userId, provider, tokenSource, success, credentialId, message, details) {
  const updateData = {
    injected_to_n8n: success,
    injected_at: success ? new Date().toISOString() : null,
    injection_error: success ? null : message,
    injection_attempted_at: new Date().toISOString(),
    injection_requested: false,
    additional_data: JSON.stringify({
      injection_method: 'direct_database_insert_with_diagnostics',
      success: success,
      error: success ? null : message,
      details: details || {},
      timestamp: new Date().toISOString(),
      version: '7.0'
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
    throw new Error(`Supabase update failed: ${error.message}`);
  }

  console.log('  ✅ Supabase status updated');
}

// Run
main().catch(error => {
  console.error('💥 Unhandled error:', error);
  process.exit(1);
});
