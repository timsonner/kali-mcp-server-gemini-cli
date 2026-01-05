# Gemini Operator Guide

Quick reference for using AI agents with the Kali MCP server for security testing.

## Quick Start

The agent has access to the `penetration-testing` skill which provides comprehensive pentesting methodology. Simply describe your objective and the agent will follow structured testing procedures.

### Example Prompts

**Basic Target Assessment**:
```
Perform a security assessment of [TARGET_IP]. Find any flags and document all findings.
```

**With Hints**:
```
Test [TARGET_IP] for vulnerabilities. Hint: there's a custom web application running.
```

**Specific Objective**:
```
CTF challenge at [TARGET_IP]. Enumerate services, find entry point, escalate privileges, 
and retrieve user/root flags. Track all commands used.
```

**From TryHackMe/HTB**:
```
TryHackMe room "[ROOM_NAME]" deployed at [TARGET_IP]. Complete the challenge and 
document the exploitation path.
```

## Critical Reminders

When working with the agent, ensure they:

**Use timeouts on network commands**
- `curl -m 10` not just `curl`
- `timeout 5s nc` not just `nc`
- `timeout 300s nmap` for long scans

**Handle tool availability gracefully**
- Install tools on first use: `apt-get update && apt-get install -y [TOOL]`
- After successful install, okay to assume tool is available
- If command fails, install/adjust command accordingly and retry
- Be resilient: adapt to errors rather than abort

**Log everything**
- Maintain `pentest_log.md` throughout testing
- Document successful AND failed attempts
- Track all discovered credentials/files

**Attribute external code**
- Document source URLs for any downloaded scripts/exploits
- Include repository links, Exploit-DB IDs, or author attribution
- Note if exploit was modified from original
- Custom agent-written scripts don't need attribution

**Generate final report**
- Request `vulnerability_report.md` at completion
- Should include severity ratings and remediation steps

**Preserve all files**
- Never delete files from the Kali container
- Keep all tools, scripts, logs, and results
- Evidence preservation is critical for review
- Container persistence maintains installed tools for future use

## Agent Skills Integration

The agent automatically discovers and uses the `penetration-testing` skill when:
- You mention security testing, pentesting, CTF, vulnerability scanning
- You provide a target IP or hostname
- You ask to find flags or exploit vulnerabilities

**Manual activation** (if needed):
```
Use the penetration-testing skill to assess [TARGET_IP]
```

## Typical Workflow

1. **Initial Prompt**: Describe target and objective
2. **Agent Enumeration**: Port scanning, service discovery
3. **Agent Exploitation**: Vulnerability testing, gaining access
4. **Agent Escalation**: Privilege escalation, flag retrieval
5. **Report Generation**: Request comprehensive vulnerability report

The agent follows structured methodology from `skills/penetration-testing/SKILL.md` automatically.

## Getting Unstuck

If the agent seems stuck:

```
Try alternative approaches:
- Different enumeration tools
- Manual testing instead of automated scans
- Check for configuration files or backups
- Try a completely different attack vector
```

## Common Scenarios

### CTF/Challenge Boxes
```
Complete the [PLATFORM] challenge at [TARGET_IP]:
- Enumerate all services
- Find vulnerabilities
- Gain initial access
- Escalate to root
- Retrieve all flags

Document the full exploitation chain.
```

### Vulnerability Assessment
```
Conduct a vulnerability assessment of [TARGET_IP]:
- Identify all running services
- Test for common vulnerabilities (SQLi, RCE, misconfigurations)
- Document severity and remediation steps
- Generate professional report
```

### Web Application Testing
```
Test the web application at http://[TARGET_IP]:
- Directory enumeration
- Input validation testing
- Authentication bypass attempts
- File upload vulnerabilities

Focus on OWASP Top 10 issues.
```

## Best Practices

### For Effective Agent Use
- **Be specific** about objectives (find flags, test specific service, full assessment)
- **Provide context** if available (hints, known vulnerabilities, challenge descriptions)
- **Set scope** clearly (in-scope IPs, ports, URLs)
- **Request logs** regularly to monitor progress
- **Allow creativity** - let agent try multiple approaches

### For Agent
The agent should follow `skills/penetration-testing/SKILL.md` methodology:
1. Reconnaissance
2. Vulnerability Assessment
3. Exploitation
4. Privilege Escalation
5. Report Generation

## Output Files

Expect these files to be created/updated:
- `pentest_log.md` - Running log of all commands and findings
- `vulnerability_report.md` - Final comprehensive report
- `scan_results.txt`, `nikto_results.txt` - Tool outputs
- Custom scripts (saved to `/tmp/` in container)

## Troubleshooting

**Agent not using timeouts**:
```
Reminder: Always use timeouts on network commands (curl -m 10, timeout 5s nc)
```

**Missing tools**:
```
Install necessary tools first: apt-get update && apt-get install -y [TOOLS]
```

**Incomplete logging**:
```
Update pentest_log.md with all recent commands and findings
```

**Agent trying to clean up**:
```
Do not delete any files from the Kali container. Preserve all evidence, tools, and results.
```

**Need more detail**:
```
Check skills/penetration-testing/references/ATTACK_PATTERNS.md for specific payloads
```

## Advanced Usage

### Multi-Target Testing
```
Assess network range [IP_RANGE]:
- Discover live hosts
- Scan all hosts for services
- Prioritize by attack surface
- Test highest-value targets

Maintain separate logs per target.
```

### With VPN (TryHackMe/HTB)
```
1. Copy VPN config: [shows how in README.md VPN section]
2. Connect to VPN in Kali container
3. Verify connectivity: ping [TARGET_IP]
4. Begin assessment
```

### Custom Requirements
```
Test [TARGET] with these constraints:
- Stealth mode (slower scans, avoid IDS)
- Web-only (no network-level attacks)
- No bruteforce (avoid account lockouts)
- Specific tools only (nmap, curl, manual testing)
```

## Quick Reference

**MCP Tools Available**:
- `kali-exec` - Execute commands in Kali container
- `kali-container-status` - Check container state
- `kali-container-restart` - Restart container
- `kali-container-stop` - Stop container

**Essential Commands**:
```bash
# Install toolkit
apt-get update && apt-get install -y nmap nikto hydra dirb netcat-traditional curl

# Quick scan
nmap -T4 --top-ports 1000 [TARGET]

# Web enumeration
gobuster dir -u http://[TARGET] -w /usr/share/wordlists/dirb/common.txt

# Search exploits
searchsploit [SERVICE] [VERSION]
```

**Resources**:
- Skill methodology: `skills/penetration-testing/SKILL.md`
- Attack patterns: `skills/penetration-testing/references/ATTACK_PATTERNS.md`
- Full README: Project root

---

**Remember**: The agent is autonomous once given clear objectives. Provide the target, describe the goal, and let the penetration-testing skill guide the workflow.
