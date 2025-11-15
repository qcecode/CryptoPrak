# Build Instructions (Ubuntu/Linux)

## Requirements

- .NET 9.0 SDK

## Building the project

```bash
# Build entire project
dotnet build

# Or build only Prak02
dotnet build src/Prak02/Prak02.csproj
```

## Prak 2

```bash
# From project directory:
dotnet run --project src/Prak02/Prak02.csproj

# Or run directly after build:
dotnet src/Prak02/bin/Debug/net9.0/Prak02.dll
```

The program automatically performs a Meet-in-the-Middle attack on Double-DES.

### Notes

- The project uses a native Linux library (`libdestoy.so`) which is included
- Tested on Ubuntu with x86-64 architecture
