# Etapa base
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app

ENV TZ=America/Costa_Rica
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# First update and install packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iputils-ping \
    dnsutils \
    curl \
    net-tools && \
    rm -rf /var/lib/apt/lists/*

# Then create directories and set permissions
RUN mkdir -p /app/keys && \
    chmod -R 770 /app/keys

EXPOSE 8081
ENV ASPNETCORE_URLS=http://*:8081
ENV ASPNETCORE_ENVIRONMENT=Development

# Etapa de build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["AccionSocial.api/AccionSocial.api.csproj", "AccionSocial.api/"]
RUN dotnet restore "AccionSocial.api/AccionSocial.api.csproj"
COPY . .
WORKDIR "/src/AccionSocial.api"
RUN dotnet build "AccionSocial.api.csproj" -c Release -o /app/build

# Etapa de publicación
FROM build AS publish
RUN dotnet publish "AccionSocial.api.csproj" -c Release -o /app/publish /p:UseAppHost=false


# Etapa final
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Crear directorios y establecer permisos sin usuario específico
RUN mkdir -p /app/uploads /app/wwwroot && \
    chmod -R 775 /app/uploads /app/wwwroot

ENTRYPOINT ["dotnet", "AccionSocial.api.dll"]