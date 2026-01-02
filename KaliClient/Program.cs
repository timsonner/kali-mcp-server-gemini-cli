using System.Diagnostics;
using System.Text.Json;

namespace KaliClient;

class Program
{
    static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  Run command: dotnet run -- \"ls -la\"");
            Console.WriteLine("  Check status: dotnet run -- kali-container-status");
            Console.WriteLine("  Restart:      dotnet run -- kali-container-restart");
            Console.WriteLine("  Stop:         dotnet run -- kali-container-stop");
            return;
        }

        string inputArg = args[0];
        string toolName;
        object toolArguments;

        // Simple logic to switch between tools
        if (inputArg.StartsWith("kali-container-"))
        {
            toolName = inputArg;
            toolArguments = new { containerName = "kali-mcp-container" };
        }
        else
        {
            toolName = "kali-exec";
            toolArguments = new 
            { 
                command = inputArg,
                image = "kalilinux/kali-rolling",
                containerName = "kali-mcp-container"
            };
        }

        // Check if a kali-mcp container is already running (e.g., from VS Code)
        string? runningContainer = GetRunningKaliMcpContainer();
        
        ProcessStartInfo psi;
        if (runningContainer != null)
        {
            Console.Error.WriteLine($"Using existing container: {runningContainer}");
            // Use docker exec to connect to running container's MCP server stdin/stdout
            psi = new ProcessStartInfo
            {
                FileName = "docker",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("exec");
            psi.ArgumentList.Add("-i");
            psi.ArgumentList.Add(runningContainer);
            psi.ArgumentList.Add("dotnet");
            psi.ArgumentList.Add("KaliMCP.dll");
        }
        else
        {
            // Load configuration and start new container
            string? settingsPath = Environment.GetEnvironmentVariable("GEMINI_SETTINGS_PATH");
            
            if (string.IsNullOrEmpty(settingsPath))
            {
                settingsPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../.gemini/settings.json"));
            }
            
            if (!File.Exists(settingsPath))
            {
                Console.Error.WriteLine($"Error: Settings file not found at {settingsPath}");
                Console.Error.WriteLine("Tip: Set GEMINI_SETTINGS_PATH environment variable to specify a custom location.");
                return;
            }

            string jsonString = await File.ReadAllTextAsync(settingsPath);
            using JsonDocument configDoc = JsonDocument.Parse(jsonString);
            
            var mcpServers = configDoc.RootElement.GetProperty("mcpServers");
            var firstServer = mcpServers.EnumerateObject().First();
            var serverConfig = firstServer.Value;

            string command = serverConfig.GetProperty("command").GetString()!;
            var argsArray = serverConfig.GetProperty("args");
            
            psi = new ProcessStartInfo
            {
                FileName = command,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in argsArray.EnumerateArray()) psi.ArgumentList.Add(arg.GetString()!);
        }

        using var process = new Process { StartInfo = psi };
        process.Start();

        // Drain stderr in background to prevent buffer blocking
        Task.Run(async () => { while (!process.StandardError.EndOfStream) await process.StandardError.ReadLineAsync(); });

        try 
        {
            // Helper to read next valid JSON-RPC line (skips non-JSON output like Docker logs)
            async Task<string?> ReadJsonLineAsync(int timeoutSeconds = 120)
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
                try
                {
                    while (!cts.Token.IsCancellationRequested)
                    {
                        var readTask = process.StandardOutput.ReadLineAsync(cts.Token);
                        string? line = await readTask;
                        if (line == null) return null;
                        if (line.TrimStart().StartsWith("{")) return line;
                        // Skip non-JSON lines (e.g., Docker daemon startup logs)
                        Console.Error.WriteLine($"[Skipping non-JSON]: {line}");
                    }
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine("Timeout waiting for MCP server response");
                }
                return null;
            }

            // 3. Initialize (wait longer for first response as Docker daemon starts up)
            var initRequest = new
            {
                jsonrpc = "2.0", id = 1, method = "initialize",
                @params = new { protocolVersion = "2024-11-05", capabilities = new { }, clientInfo = new { name = "cli-client", version = "1.0" } }
            };
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(initRequest));
            var initResponse = await ReadJsonLineAsync(120); // 2 min timeout for startup
            if (initResponse == null)
            {
                Console.Error.WriteLine("Failed to initialize MCP server");
                return;
            } 

            // 4. Call Tool
            var toolRequest = new
            {
                jsonrpc = "2.0", id = 2, method = "tools/call",
                @params = new { name = toolName, arguments = toolArguments }
            };

            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(toolRequest));
            string? responseJson = await ReadJsonLineAsync(60); // 1 min timeout for tool execution

            if (responseJson != null)
            {
                // Debug: Print raw response if parsing fails
                try 
                {
                    using var responseDoc = JsonDocument.Parse(responseJson);
                    if (responseDoc.RootElement.TryGetProperty("result", out var result) &&
                        result.TryGetProperty("content", out var content) &&
                        content.GetArrayLength() > 0)
                    {
                        Console.WriteLine(content[0].GetProperty("text").GetString());
                    }
                    else
                    {
                        Console.WriteLine(responseJson);
                    }
                }
                catch (JsonException)
                {
                    Console.WriteLine($"Failed to parse JSON response: {responseJson}");
                }
            }
        }
        finally
        {
            process.Kill();
        }
    }

    /// <summary>
    /// Check if a kali-mcp container is already running and return its name
    /// </summary>
    static string? GetRunningKaliMcpContainer()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "docker",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("ps");
        psi.ArgumentList.Add("-q");
        psi.ArgumentList.Add("--filter");
        psi.ArgumentList.Add("ancestor=kali-mcp");

        using var process = new Process { StartInfo = psi };
        process.Start();
        string output = process.StandardOutput.ReadToEnd().Trim();
        process.WaitForExit();

        if (process.ExitCode == 0 && !string.IsNullOrEmpty(output))
        {
            // Return first container ID found
            return output.Split('\n')[0];
        }
        return null;
    }
}