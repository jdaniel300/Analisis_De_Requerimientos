# Etapa de construcción
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["AccionSocial.web/AccionSocial.web.csproj", "AccionSocial.web/"]
COPY ["AccionSocialModels/AccionSocialModels.csproj", "AccionSocialModels/"]
RUN dotnet restore "AccionSocial.web/AccionSocial.web.csproj"

COPY . .
WORKDIR "/src/AccionSocial.web"
RUN dotnet build "AccionSocial.web.csproj" -c Release -o /app/build

# Etapa de publicación
FROM build AS publish
RUN dotnet publish "AccionSocial.web.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Etapa final
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Configuración básica para desarrollo
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Development
EXPOSE 8080

ENTRYPOINT ["dotnet", "AccionSocial.web.dll"]