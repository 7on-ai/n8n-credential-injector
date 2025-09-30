# Dockerfile for N8N Credential Injector Service
FROM node:20-alpine

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    sqlite \
    curl \
    postgresql-client \
    bash

# Set working directory
WORKDIR /app

# Create package.json with pg dependency
RUN echo '{ \
  "name": "n8n-credential-injector", \
  "version": "7.0.0", \
  "type": "module", \
  "main": "injector.js", \
  "dependencies": { \
    "@supabase/supabase-js": "^2.38.0", \
    "pg": "^8.11.3" \
  } \
}' > package.json

# Install dependencies
RUN npm install

# Install n8n CLI globally
RUN npm install -g n8n@latest

# Verify n8n CLI installation
RUN n8n --version

# Copy the injector script
COPY injector.js /app/injector.js

# Create temp directory and set permissions
RUN mkdir -p /tmp && chmod 777 /tmp

# Set proper permissions for node user
RUN chown -R node:node /app

# Switch to non-root user
USER node

# Default command runs the injector
CMD ["node", "injector.js"]
