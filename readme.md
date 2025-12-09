# Praktikum 3: Diskrete Logarithmen – Baby-Step Giant-Step

## Build Instructions (Ubuntu/Linux)

### Requirements
- .NET 9.0 SDK

### Building the project
```bash
# Build entire project
dotnet build

# Or build only Prak03
dotnet build src/Prak03/Prak03.csproj
```

### Running Prak03
```bash
# From project directory:
dotnet run --project src/Prak03/Prak03.csproj

# Or run directly after build:
dotnet src/Prak03/bin/Debug/net9.0/Prak03.dll
```

### Expected Output
The program automatically:
- Solves the discrete logarithm problem using Baby-Step Giant-Step algorithm
- Demonstrates space-time trade-offs with different k-factors (0.1, 0.5, 1.0, 2.0, 5.0)


### Notes
- Pure .NET implementation, no native libraries required
- Tested on macOS with arm architecture
- Works on any platform with .NET 9.0 SDK (Windows, macOS, Linux)

---

## Antworten zu den Aufgaben

### Teil (b): Zeit- und Speicherkomplexität

**Zeit- und Speicherkomplexität:**

| Algorithmus | Zeitkomplexität | Speicherkomplexität |
|-------------|-----------------|---------------------|
| **BSGS** | O(√n) | O(√n) |
| **Brute-Force** | O(n) | O(1) |

wobei n = p - 1 = 6971096458

**Verbesserung:**

BSGS ist √n mal schneller als Brute-Force.

Für p = 6971096459:
- n = 6.971.096.458
- √n ≈ 83.494
- **Verbesserungsfaktor: ~83×**

**Erklärung des Trade-offs:**

Der Baby-Step Giant-Step Algorithmus tauscht Speicher gegen Zeit:
- Er verwendet O(√n) zusätzlichen Speicher für die Hash-Tabelle der Baby-Steps
- Dadurch reduziert sich die Laufzeit von O(n) auf O(√n)
- Dies ist ein klassisches Beispiel für ein **Time-Space Trade-off**

**Warum ist BSGS effizienter?**

Der Algorithmus vermeidet die vollständige Enumeration durch:
1. **Baby-Steps:** Vorberechnung von g^j für j = 0 bis m-1 (Speicherung in Hash-Tabelle)
2. **Giant-Steps:** Berechnung von h·(g^(-m))^i und Lookup in der Tabelle
3. Bei einem Match gilt: g^(i·m+j) ≡ h (mod p), also x = i·m + j

Statt alle p-1 Exponenten zu testen, benötigt BSGS nur etwa 2√n Operationen.

---

### Teil (c): Space-Time Trade-off Modifikation

**Antwort:**

Ja, es gibt einen Space-Time Trade-off im BSGS-Algorithmus.

**Prinzip:**

Statt m = √n zu wählen, können wir einen beliebigen Wert m wählen:
- **Größeres m** → mehr Speicher, weniger Giant-Steps (theoretisch schneller)
- **Kleineres m** → weniger Speicher, mehr Giant-Steps (langsamer)

**Mathematische Analyse:**

Die Gesamtkomplexität beträgt O(m + n/m), wobei:
- m = Anzahl der Baby-Steps (Speicherverbrauch)
- n/m = Anzahl der Giant-Steps (maximale Iterationen)

Diese Funktion wird bei m = √n minimiert.

**Implementierung:**

Der Trade-off wird durch Variation von m realisiert:
```csharp
var m = (BigInteger)((double)m_optimal / k_factor);
```

wo:
- k_factor < 1: Mehr Speicher (größeres m)
- k_factor = 1: Standard BSGS (optimal)
- k_factor > 1: Weniger Speicher (kleineres m)
