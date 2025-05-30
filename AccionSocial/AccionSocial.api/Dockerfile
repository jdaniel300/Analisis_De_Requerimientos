WORKDIR /src
COPY ["AccionSocial.api/AccionSocial.api.csproj", "AccionSocial.api/"]
RUN dotnet restore "AccionSocial.api/AccionSocial.api.csproj"
COPY . .
WORKDIR "/src/AccionSocial.api"
RUN dotnet build "AccionSocial.api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AccionSocial.api.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AccionSocial.api.dll"]