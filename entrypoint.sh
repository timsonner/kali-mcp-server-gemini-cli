#!/bin/bash
# Start Docker daemon in the background
dockerd > /var/log/dockerd.log 2>&1 &

# Wait for Docker to start
MAX_RETRIES=30
RETRIES=0
while ! docker info > /dev/null 2>&1; do
    RETRIES=$((RETRIES + 1))
    if [ $RETRIES -ge $MAX_RETRIES ]; then
        echo "Docker daemon failed to start"
        cat /var/log/dockerd.log
        exit 1
    fi
    sleep 1
done

echo "Docker daemon is running."

# Execute the MCP server
dotnet KaliMCPGemini.dll
