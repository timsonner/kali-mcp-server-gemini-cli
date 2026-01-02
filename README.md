# Kali MCP Gemini Server

A .NET-based [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that provides a persistent Kali Linux environment for Gemini agents.

## Project Structure

```
.
├── Dockerfile
├── entrypoint.sh
├── run_mcp.sh
├── README.md
├── .gemini/
│   └── settings.json
├── .vscode/
│   └── mcp.json
├── KaliMCPGemini/
│   ├── KaliMCPGemini.csproj
│   ├── Program.cs
│   └── Tools/
│       └── KaliLinuxToolset.cs
└── KaliClient/
    ├── KaliClient.csproj
    └── Program.cs
```

- **`KaliMCPGemini/`**: The core MCP server implementation in C#
- **`KaliClient/`**: A reference .NET client that demonstrates MCP protocol usage
- **`Dockerfile`**: Multi-stage build for the MCP server with Docker-in-Docker support
- **`.gemini/settings.json`**: Gemini CLI configuration
- **`.vscode/mcp.json`**: VS Code MCP configuration

## Architecture: Docker-in-Docker (DinD)

Uses **Docker-in-Docker** with `--privileged` flag to run an internal Docker daemon. The Kali environment runs in a nested container, isolated from the host's Docker daemon and filesystem.

**Benefits**: Compromised Kali container cannot access host Docker daemon.

**Learn more**: [Docker Hub DinD Docs](https://hub.docker.com/_/docker#what-is-docker-in-docker) • [Docker Blog](https://www.docker.com/blog/docker-can-now-run-within-docker/)

## Available MCP Tools

Four MCP protocol tools for container management and command execution:

**`kali-exec`** - Execute commands in Kali container
- `command` (required): Bash command to run
- `image` (optional): Docker image (default: `kalilinux/kali-rolling`)
- `containerName` (optional): Container name (default: `kali-mcp-gemini-persistent`)

**`kali-container-status`** - Check container status
- `containerName` (optional)

**`kali-container-restart`** - Restart container
- `containerName` (optional)
- `image` (optional)

**`kali-container-stop`** - Stop/remove container
- `containerName` (optional)
- `removeContainer` (optional): Delete container if true

## Setup

**Prerequisites**: Docker Desktop running + .NET 9.0 SDK

```bash
# Verify environment
dotnet --version  # Should be 9.0+
docker ps         # Should succeed

# Build MCP server image
docker build -t kali-mcp-gemini .

# Pull Kali image
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

## Kali Linux Tools

⚠️ **Minimal Base Image**: `kalilinux/kali-rolling` does not include most security tools (nmap, metasploit, nikto, etc.). You must install them first.

```bash
apt-get update
apt-get install -y nmap iputils-ping netcat-traditional dnsutils
apt-get install -y metasploit-framework nikto sqlmap wpscan
```

✅ **Persistence**: Installed tools persist across restarts via Docker volume mount (`-v kali_mcp_data:/var/lib/docker` in `.gemini/settings.json`). This volume stores the internal Docker daemon's state, including all container filesystems and installed packages. Install once, use forever.

## Running the Server

**Gemini CLI** (AI Agents): Auto-discovered via `.gemini/settings.json`. Includes `--privileged` flag and `kali_mcp_data` volume for persistence.

**VS Code** (Copilot): Auto-discovered via `.vscode/mcp.json`.

**Local Dev** (Debugging): Run `./run_mcp.sh` to bypass Docker (less isolation).

## Usage

### Gemini CLI

Interact with Kali through natural language:

```bash
# Discover tools
gemini> What MCP tools are available?

# kali-exec - Execute commands
gemini> Run "apt-get update && apt-get install -y nmap" in Kali
gemini> Use nmap to scan 192.168.1.0/24

# kali-container-status - Check status
gemini> Is my Kali container running?

# kali-container-restart - Restart container
gemini> Restart the Kali container

# kali-container-stop - Stop container
gemini> Stop the Kali container
```

### VS Code

Use `@workspace` prefix:

```
@workspace What Kali MCP tools are available?
@workspace Install nmap in the Kali container
@workspace Check if the Kali container is running
@workspace Run an nmap scan on localhost
```

### Reference Client

Demonstrates programmatic MCP interaction. Run from project root:

```bash
# Execute commands
dotnet run --project KaliClient -- "cat /etc/os-release"

# Container management
dotnet run --project KaliClient -- kali-container-status
dotnet run --project KaliClient -- kali-container-restart

# Custom settings path
export GEMINI_SETTINGS_PATH="/path/to/settings.json"
```

## Replicating Vulnerability Assessments

This repository includes sample vulnerability assessment workflows.

### Example 1: DVWA (Local Docker)

#### 1. Target Setup
To replicate the findings in [Vulnerability_Report.md](Vulnerability_Report.md), start a DVWA container on your host machine:

```bash
docker run --rm -it -p 8080:80 vulnerables/web-dvwa
```

*Note: To access the DVWA container on `localhost`, ensure the MCP server is running with Host Networking enabled (default in provided configuration). Otherwise, use your host's IP address (e.g., `host.docker.internal` on Docker Desktop).*

#### 2. Session Workflow
The following prompts were used with the Kali MCP agent to generate the report:

1.  **Environment Prep**:
    > "Install necessary security tools (nikto, hydra, wordlists, curl, net-tools) in the Kali container."

2.  **Vulnerability Testing**:
    > "Perform a vulnerability assessment of the DVWA target at http://localhost:8080. Test for SQL Injection, Command Injection, Brute Force, XSS, and Server Configuration issues."

3.  **Reporting**:
    > "Generate a comprehensive markdown report (Vulnerability_Report.md) summarizing the findings, including severity, evidence, and remediation steps."

#### 3. View Results
See the generated report: **[Vulnerability_Report.md](Vulnerability_Report.md)**

### Example 2: Pyrat (TryHackMe)

#### 1. Target Setup
Deploy the [Pyrat](https://tryhackme.com/r/room/pyrat) room on TryHackMe and note the target IP. Ensure you have your OpenVPN configuration file ready.

#### 2. Session Workflow
The following prompts were used to conduct the assessment:

1.  **VPN Connection**:
    > "copy the .ovpn file from my downloads folder and start the vpn"

2.  **Assessment & Exploitation**:
    > run vulnerability assesment against this host. its a tryhackme room. here is the hint "Pyrat receives a curious response from an HTTP server, which leads to a potential Python code execution vulnerability. With a cleverly crafted payload, it is possible to gain a shell on the machine. Delving into the directories, the author uncovers a well-known folder that provides a user with access to credentials. A subsequent exploration yields valuable insights into the application's older version. Exploring possible endpoints using a custom script, the user can discover a special endpoint and ingeniously expand their exploration by fuzzing passwords. The script unveils a password, ultimately granting access to the root."

    > "focus on manual enumeration", and "keep playing with the custom app" install tools as needed, see if you can find the flags on <target IP> using kali-exec. make sure to keep track of commands and techniques used as we'll generate a report if vulneravilities are found.

3.  **MCP Tool**    
    > "make sure to use the mcp tool kali-exec for enumeration and testing.

4.  **Timeouts**
    > make sure to use timeouts so you're not getting stuck waiting for socket responses

#### 3. View Results
See the generated report: **[Pyrat_Vulnerability_Report.md](Pyrat_Vulnerability_Report.md)**

## Connect container to VPN

The Kali container supports VPN connections (e.g., OpenVPN) using Host Networking and `NET_ADMIN` capabilities.

**1. Rebuild and Restart**
Ensure the container is running with the latest network flags:
```bash
# Rebuild the MCP server image
docker build -t kali-mcp-gemini .

# Restart the container (applies new flags)
dotnet run --project KaliClient -- kali-container-restart
```

**2. Copy VPN Configuration**
Copy your `.ovpn` file from the host to the container:
```bash
docker cp ~/path/to/your.ovpn kali-mcp-gemini-persistent:/root/vpn.ovpn
```

**3. Install Tools & Connect**
Install OpenVPN and start the connection in a background screen session:
```bash
# Install tools
dotnet run --project KaliClient -- "apt-get update && apt-get install -y openvpn screen iputils-ping iproute2 net-tools"

# Start VPN
dotnet run --project KaliClient -- "screen -dmS vpn openvpn --config /root/vpn.ovpn"
```

**4. Verify Connection**
Check the `tun0` interface:
```bash
dotnet run --project KaliClient -- "ip addr show tun0"
```

## Troubleshooting

**Docker daemon failed**: Verify `--privileged` flag in config, Docker Desktop running, check logs

**Network/DNS issues**: Ensure `--network host` in `.gemini/settings.json`

**Settings file not found**: Run from project root or set `GEMINI_SETTINGS_PATH`

**Docker not found**: Build image, verify Docker running, pull Kali image

**.NET version mismatch**: Install .NET 9.0+ from https://dotnet.microsoft.com/download

**Unresponsive container**: Restart via `kali-container-restart` or stop/remove

## Security

⚠️ **Requires `--privileged` flag** for DinD support.

**Isolation**: Internal Docker daemon prevents Kali container from accessing host Docker daemon or containers. Agent commands restricted to nested environment.

**Best Practices**:
- Trust the image before running with `--privileged`
- Monitor `kali-exec` commands
- Don't expose to untrusted networks
