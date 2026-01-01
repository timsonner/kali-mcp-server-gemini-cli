# Use the .NET SDK image to build the application
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy the project file and restore dependencies
COPY ["KaliMCPGemini/KaliMCPGemini.csproj", "KaliMCPGemini/"]
RUN dotnet restore "KaliMCPGemini/KaliMCPGemini.csproj"

# Copy the rest of the source code
COPY . .
WORKDIR "/src/KaliMCPGemini"
RUN dotnet build "KaliMCPGemini.csproj" -c Release -o /app/build

# Publish the application
FROM build AS publish
RUN dotnet publish "KaliMCPGemini.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final stage: Create the runtime image
FROM mcr.microsoft.com/dotnet/runtime:9.0 AS final
WORKDIR /app

# Install Docker Engine (DinD)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    procps \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io \
    && rm -rf /var/lib/apt/lists/*

# Copy the published application
COPY --from=publish /app/publish .

# Copy and set the entrypoint script
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Set the entry point to our script
ENTRYPOINT ["./entrypoint.sh"]
