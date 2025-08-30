#!/bin/bash

echo "Generating keys for FC Sync server..."

# Generate JWT signing key
JWT_KEY=$(openssl rand -base64 32)
echo "JWT_SIGNING_KEY=$JWT_KEY"

# Generate admin bearer token
ADMIN_TOKEN=$(openssl rand -base64 32)
echo "ADMIN_BEARER_TOKEN=$ADMIN_TOKEN"

# Generate admin session key
SESSION_KEY=$(openssl rand -base64 32)
echo "ADMIN_SESSION_KEY=$SESSION_KEY"

# Generate federation token
FEDERATION_TOKEN=$(openssl rand -base64 32)
echo "FEDERATION_TOKEN=$FEDERATION_TOKEN"

echo ""
echo "Add these to your .env file or environment variables."
echo ""
echo "For admin password hash, run:"
echo "htpasswd -bnBC 12 \"\" your-password | tr -d ':\\n'"
