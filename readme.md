# Praktikum 4: Baby-SHA Hash Function

## Build Instructions

### Requirements
- .NET 10.0 SDK

### Running Prak04
```bash
dotnet run --project src/Prak04/Prak04.csproj
```

---

## Task 1: Properties of Cryptographic Hash Functions

### Task 1a: Preimage-Angriff

**Ziel:** Finde ein alphanumerisches Passwort, das den Hash `d44a0fd4` erzeugt.

**Methode:** Brute-Force über alle alphanumerischen Kombinationen (a-z, A-Z, 0-9) mit steigender Länge.

**Implementierung:** `Task1a_PreimageAttack()` in Program.cs

### Task 1b: Brute-Force-Analyse für 32-bit Plaintext

**Theoretische Analyse:**
- Keyspace: 2^32 = 4.294.967.296 mögliche Werte
- Erwartete Versuche (Durchschnitt): 2^31 ≈ 2.147.483.648
- Bei 50% Wahrscheinlichkeit nach ~2^31 Versuchen gefunden

**Praktische Analyse:** Das Programm führt einen tatsächlichen Brute-Force durch und vergleicht die Ergebnisse mit der Theorie.

---

## Task 2: Sample Applications of Cryptographic Hash Functions

### Szenario
Alice behauptet, ein Rätsel gelöst zu haben. Bob möchte es selbst lösen, will aber sicher sein, dass Alice nicht blufft.

### Lösung: Commitment Scheme

**Ablauf:**

1. **Commitment (Alice):**
   - Alice berechnet `P = BabySha(lösung)`
   - Alice sendet nur den Hash `P` an Bob
   - Dies ist der Beweis, dass Alice eine Lösung hat

2. **Bob löst das Rätsel:**
   - Bob kennt nur `P`, nicht die Lösung
   - Er kann `P` nicht missbrauchen, da Preimage-Resistenz gilt

3. **Reveal (Alice):**
   - Alice enthüllt ihre Lösung an Bob

4. **Verification (Bob):**
   - Bob berechnet `BabySha(alice_lösung)`
   - Prüft ob `BabySha(alice_lösung) == P`

**Warum funktioniert das?**

| Eigenschaft | Garantie |
|-------------|----------|
| **Preimage-Resistenz** | Bob kann aus `P` nicht die Lösung berechnen |
| **Binding** | Alice kann später keine andere Lösung präsentieren, die denselben Hash `P` erzeugt |

**Beispiel:**
```
Alice's Lösung: "42"
P = BabySha("42") = 8f3a2b1c

Alice sendet P an Bob → Bob kann "42" nicht aus 8f3a2b1c ableiten
Bob löst selbst → findet auch "42"
Alice enthüllt "42" → Bob verifiziert: BabySha("42") == 8f3a2b1c ✓
```

