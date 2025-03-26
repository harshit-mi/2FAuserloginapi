# Use a imagem oficial do SDK do .NET como imagem base
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copie o arquivo de projeto e restaure as dependências
COPY **/*.csproj ./
RUN dotnet restore

# Copie o restante dos arquivos e compile o aplicativo
COPY . .
RUN dotnet publish -c Release -o /app/out

# Use a imagem oficial do runtime do .NET como imagem base para o contêiner final
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

# Defina o ponto de entrada do contêiner
ENTRYPOINT ["dotnet", "ecos-api.dll"]



