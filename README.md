# Kali MCP Gemini Server

A .NET-based [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that provides a persistent Kali Linux environment for Gemini agents.

## Project Structure

- **`KaliMCPGemini/`**: The core MCP server implementation in C#.
- **`KaliClient/`**: A reference .NET client that acts as a bridge for Gemini agents.
- **`Dockerfile`**: Builds the server image (`kali-mcp-gemini`).
- **`.gemini/settings.json`**: Configuration source for launching the server.

## Architecture: Docker-in-Docker (DinD)

This project uses **Docker-in-Docker (DinD)** for enhanced security and isolation.
The MCP server container runs with the `--privileged` flag and hosts its own internal Docker daemon. This ensures that the Kali Linux environment and any commands executed within it are isolated from the host machine's Docker daemon and file system.

### Key Benefits:
- **Isolation**: Compromise of the Kali container does not provide access to the host Docker daemon.
- **Clean Slate**: Each server instance starts with a fresh Docker environment.

### Requirements:
- The server container **must** be run with the `--privileged` flag to allow the internal Docker daemon to function.

## Available Tools

The server exposes the following MCP tools. Agents should generally access these via the provided `KaliClient`.

### 1. `kali-exec`
Executes a shell command inside the persistent Kali container.
- **Arguments**:
    - `command` (string, required): The bash command to run (e.g., `nmap 192.168.1.1`).
    - `image` (string, optional): Docker image to use (default: `kalilinux/kali-rolling`).
    - `containerName` (string, optional): Container name (default: `kali-mcp-gemini-persistent`).

### 2. `kali-container-status`
Checks the status of the persistent container.
- **Arguments**:
    - `containerName` (string, optional)

### 3. `kali-container-restart`
Restarts the persistent container (useful if a tool hangs or networking breaks).
- **Arguments**:
    - `containerName` (string, optional)
    - `image` (string, optional)

### 4. `kali-container-stop`
Stops (and optionally removes) the container.
- **Arguments**:
    - `containerName` (string, optional)
    - `removeContainer` (boolean, optional): If true, deletes the container (default: `false`).

## Setup

1.  **Prerequisites**:
    -   **Docker Desktop** (or Docker Engine) installed and **running**.
    -   .NET 9.0 SDK or later.
    
    **Verify your environment**:
    ```bash
    # Check .NET version (should be 9.0.0 or higher)
    dotnet --version
    
    # Check Docker is running (should show container list or empty table)
    docker ps
    ```

2.  **Build the Server Image**:
    This step is critical. You must build the image before running any clients.
    ```bash
    docker build -t kali-mcp-gemini .
    ```

3.  **Pull Kali Image**:
    Pre-pulling the image ensures the first run is faster and avoids timeouts.
    ```bash
    docker pull kalilinux/kali-rolling
    ```

## Quick Start

After cloning the repository, verify everything works:

```bash
# 1. Verify prerequisites
dotnet --version  # Should be 9.0.0 or higher
docker ps         # Should succeed without errors

# 2. Build the Docker image
docker build -t kali-mcp-gemini .

# 3. Pull the Kali Linux image
docker pull kalilinux/kali-rolling

# 4. Test with KaliClient (ensure you're in the project root)
dotnet run --project KaliClient -- "echo 'Hello from Kali'"

# Expected output should show:
# Container: kali-mcp-gemini-persistent
# Command: echo 'Hello from Kali'
# ExitCode: 0
# Stdout:
# Hello from Kali
```

## Running the Server

Choose the appropriate method based on your use case:

### 1. Gemini CLI (Recommended for AI Agents)

**Best for**: Production use with Gemini AI agents

The server is automatically discovered by the Gemini CLI using the configuration in `.gemini/settings.json`. 

**Configuration Note**:
The `.gemini/settings.json` file is pre-configured with necessary flags:
- `--privileged`: Required for Docker-in-Docker.
- `--network host`: Required for proper networking inside the nested container.
- `-v kali_mcp_data:/var/lib/docker`: Persists the internal Docker state (images and containers) so your Kali environment survives between sessions.

**Requirements**:
- Docker image must be built first (`docker build -t kali-mcp-gemini .`)
- Runs in isolated Docker container with DinD

### 2. VS Code (Recommended for Development with AI Assistants)

**Best for**: Using VS Code Copilot or GitHub Copilot with MCP integration

To use the server in VS Code:
- The `.vscode/mcp.json` configuration is already included in the repository
- VS Code will automatically discover and use the MCP server
- Runs in Docker container for isolation

### 3. Local Development (Recommended for Debugging)

**Best for**: Debugging the MCP server code itself

To run the server directly on your host machine for development or debugging:
```bash
chmod +x run_mcp.sh
./run_mcp.sh
```

⚠️ **Note**: This bypasses Docker and uses your host's Docker daemon directly (less isolation). Requires Docker CLI available in PATH.

## Usage

### Reference Client
The `KaliClient` is a reference implementation that demonstrates how to programmatically interact with the MCP server. It reads the server configuration from `.gemini/settings.json`.

⚠️ **Important**: Run commands from the project root directory to ensure the relative path to `.gemini/settings.json` resolves correctly.

**Run a Bash Command:**
```bash
dotnet run --project KaliClient -- "cat /etc/os-release"
```

**Check Container Status:**
```bash
dotnet run --project KaliClient -- kali-container-status
```

**Restart or Stop:**
```bash
dotnet run --project KaliClient -- kali-container-restart
dotnet run --project KaliClient -- kali-container-stop
```

**Custom Settings Path:**
If you need to use a different settings file location, set the `GEMINI_SETTINGS_PATH` environment variable:
```bash
export GEMINI_SETTINGS_PATH="/path/to/custom/settings.json"
dotnet run --project KaliClient -- "ls -la"
```

### Gemini Agent Interaction
When running via the Gemini CLI, the agent can call these tools directly to interact with the Kali environment.

## Troubleshooting

### "Docker daemon failed to start" in container logs
**Cause**: Internal Docker daemon can't start inside the container.

**Solutions**:
- Ensure you're running the container with `--privileged` flag (already in `.gemini/settings.json` and `.vscode/mcp.json`)
- Verify Docker Desktop is running on the host machine
- Check container logs: `docker logs <container-name>`
- **Nested Overlayfs**: If you see storage driver errors, the `entrypoint.sh` is configured to use `vfs` driver which resolves issues with nested overlay filesystems.

### Network/DNS Issues in Kali Container
**Cause**: The nested container cannot resolve domains (e.g., during `apt-get update` or `docker pull`).

**Solutions**:
- Ensure the MCP server container is running with `--network host`. This is configured in `.gemini/settings.json`.

### KaliClient error: "Settings file not found"
**Cause**: Can't locate `.gemini/settings.json`.

**Solutions**:
- Ensure you're running from the project root directory
- Verify `.gemini/settings.json` exists (included in git)
- Use `GEMINI_SETTINGS_PATH` environment variable to specify custom location

### "docker: not found" when running KaliClient tests
**Cause**: Docker image not built or Docker not running.

**Solutions**:
- Build the server image: `docker build -t kali-mcp-gemini .`
- Verify Docker Desktop is running: `docker ps`
- Pull Kali image: `docker pull kalilinux/kali-rolling`

### .NET SDK version mismatch
**Cause**: Wrong .NET version installed.

**Solutions**:
- Check version: `dotnet --version`
- Install .NET 9.0 SDK or later: https://dotnet.microsoft.com/download
- Verify installation: `dotnet --list-sdks`

### Container becomes unresponsive
**Cause**: Long-running command or network issue in Kali container.

**Solutions**:
- Restart container: `dotnet run --project KaliClient -- kali-container-restart`
- Stop and remove: `dotnet run --project KaliClient -- kali-container-stop` (with `removeContainer: true`)
- Check container status: `docker exec kali-mcp-gemini-persistent ps aux`

### Permission denied errors in Kali container
**Cause**: Some tools require root privileges.

**Solutions**:
- Most commands run as root by default in the Kali container
- For specific permission issues, use `sudo` in your command
- Example: `dotnet run --project KaliClient -- "sudo apt-get update"`

## Security Implications

⚠️ **Privileged Mode Required** ⚠️

To support Docker-in-Docker (DinD), the MCP server container must be run with the `--privileged` flag. This allows the internal Docker daemon to manage containers and networking.

### Isolation and Safety:
1.  **Host Protection**: Unlike standard Docker-based tools that bind to `/var/run/docker.sock`, this server uses an internal Docker daemon. This means the Kali Linux container and its commands **cannot** see or control the host machine's Docker daemon or containers.
2.  **Filesystem Isolation**: The Kali environment operates within its own virtualized filesystem inside the server container, providing a strong layer of isolation from the host OS.
3.  **Restricted Scope**: While the server requires high privileges from the host to run its internal daemon, the *agent's* commands are restricted to the nested Kali environment.

### Best Practices:
- Ensure you trust the MCP server image before running it with `--privileged`.
- Monitor the commands being executed via `kali-exec` to maintain oversight of agent activity.
- Do not expose the MCP server's communication channel to untrusted networks.
