FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY CompareShopAuthAPI.csproj ./
RUN dotnet restore CompareShopAuthAPI.csproj
COPY . ./
RUN dotnet publish CompareShopAuthAPI.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish ./
EXPOSE 8080
ENV ASPNETCORE_HTTP_PORTS=8080
ENTRYPOINT ["dotnet", "CompareShopAuthAPI.dll"]
