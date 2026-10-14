FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src
COPY verify.csproj Program.cs ./
RUN dotnet publish -c Release -o /out
FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine
COPY --from=build /out /app
EXPOSE 8080
ENTRYPOINT ["dotnet", "/app/verify.dll"]
