FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["src/McpSecurityScanner.Api/McpSecurityScanner.Api.csproj", "src/McpSecurityScanner.Api/"]
COPY ["src/McpSecurityScanner.Core/McpSecurityScanner.Core.csproj", "src/McpSecurityScanner.Core/"]
COPY ["src/McpSecurityScanner.Infrastructure/McpSecurityScanner.Infrastructure.csproj", "src/McpSecurityScanner.Infrastructure/"]
RUN dotnet restore "src/McpSecurityScanner.Api/McpSecurityScanner.Api.csproj"

COPY . .
RUN dotnet publish "src/McpSecurityScanner.Api/McpSecurityScanner.Api.csproj" --configuration Release --no-restore --output /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080

COPY --from=build /app/publish .
USER $APP_UID
ENTRYPOINT ["dotnet", "McpSecurityScanner.Api.dll"]
