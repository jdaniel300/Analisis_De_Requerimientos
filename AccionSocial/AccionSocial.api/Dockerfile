# Etapa base
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8081

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
ENTRYPOINT ["dotnet", "AccionSocial.api.dll"]