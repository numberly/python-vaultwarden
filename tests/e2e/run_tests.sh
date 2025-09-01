#!/usr/bin/env bash

if [[ -z "${VAULTWARDEN_VERSION}" ]]; then
  VAULTWARDEN_VERSION="1.34.3"
fi

temp_dir=$(mktemp -d)

# Copy fixtures db to tmp
cp tests/fixtures/server/* $temp_dir

# Start Vaultwarden docker
docker run -d --name vaultwarden -v $temp_dir:/data  --env I_REALLY_WANT_VOLATILE_STORAGE=true --env ADMIN_TOKEN=admin  --restart unless-stopped -p 80:80 vaultwarden/server:${VAULTWARDEN_VERSION}

exit 0

# Wait for vaultwarden to start
sleep 3

# Set env variables
export VAULTWARDEN_URL="http://localhost:80"
export VAULTWARDEN_ADMIN_TOKEN="admin"
export BITWARDEN_URL="http://localhost:80"
export BITWARDEN_EMAIL="test-account@example.com"
export BITWARDEN_PASSWORD="test-account"
export BITWARDEN_CLIENT_ID="user.a8be340c-856b-481f-8183-2b7712995da2"
export BITWARDEN_CLIENT_SECRET="ag66paVUq4h7tBLbCbJOY5tJkQvUuT"
export BITWARDEN_TEST_ORGANIZATION="cda840d2-1de0-4f31-bd49-b30dacd7e8b0"
export BITWARDEN_DEVICE_ID="e54ba5f5-7d58-4830-8f2b-99194c70c14f"

# Run tests
hatch run  test:with-coverage

# store the exit code
TEST_EXIT_CODE=$?

# Stop and remove vaultwarden docker
docker stop vaultwarden
docker rm vaultwarden

# Remove fixtures db from tmp
rm -rf $temp_dir

# Exit with the test exit code
exit $TEST_EXIT_CODE