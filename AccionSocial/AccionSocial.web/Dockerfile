# Base stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

# Create wwwroot user and group first
RUN groupadd -r wwwroot && \
    useradd -r -g wwwroot wwwroot && \
    mkdir -p /app/keys && \
    chown -R wwwroot:wwwroot /app/keys

# Install network diagnostic tools (optional)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iputils-ping \
    dnsutils \
    curl \
    net-tools && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 8080
ENV ASPNETCORE_URLS=http://*:8080

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["AccionSocial.web/AccionSocial.web.csproj", "AccionSocial.web/"]
RUN dotnet restore "AccionSocial.web/AccionSocial.web.csproj"
COPY . .
WORKDIR "/src/AccionSocial.web"
RUN dotnet build "AccionSocial.web.csproj" -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish "AccionSocial.web.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final stage
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AccionSocial.web.dll"]