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
            // These tools take optional args, but we'll stick to defaults for simplicity
            toolArguments = new 
            { 
                containerName = "kali-mcp-gemini-persistent"
            };
        }
        else
        {
            toolName = "kali-exec";
            toolArguments = new 
            { 
                command = inputArg,
                image = "kalilinux/kali-rolling",
                containerName = "kali-mcp-gemini-persistent"
            };
        }

        // 1. Load Configuration
        // Allow override via environment variable or command-line argument
        string? settingsPath = Environment.GetEnvironmentVariable("GEMINI_SETTINGS_PATH");
        
        if (string.IsNullOrEmpty(settingsPath))
        {
            // Default: relative path from build output directory
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
        
        // 2. Prepare Process
        var psi = new ProcessStartInfo
        {
            FileName = command,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var arg in argsArray.EnumerateArray()) psi.ArgumentList.Add(arg.GetString()!);

        using var process = new Process { StartInfo = psi };
        process.Start();

        Task.Run(async () => { while (!process.StandardError.EndOfStream) await process.StandardError.ReadLineAsync(); });

        try 
        {
            // 3. Initialize
            var initRequest = new
            {
                jsonrpc = "2.0", id = 1, method = "initialize",
                @params = new { protocolVersion = "2024-11-05", capabilities = new { }, clientInfo = new { name = "cli-client", version = "1.0" } }
            };
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(initRequest));
            await process.StandardOutput.ReadLineAsync(); 

            // 4. Call Tool
            var toolRequest = new
            {
                jsonrpc = "2.0", id = 2, method = "tools/call",
                @params = new { name = toolName, arguments = toolArguments }
            };

            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(toolRequest));
            string? responseJson = await process.StandardOutput.ReadLineAsync();

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
}