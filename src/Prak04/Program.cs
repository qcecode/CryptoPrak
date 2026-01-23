using System.Diagnostics;
using System.Text;
using Prak04.BabySha;

namespace Prak04;

class Program
{
    // Ziel-Hash für Task 1a
    private const uint TargetHash = 0xd44a0fd4;

    // Alphanumerische Zeichen für Passwort-Suche
    private static readonly char[] AlphaNumeric =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".ToCharArray();

    static void Main(string[] args)
    {
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine("Praktikum 4: Baby-SHA Hash Function");
        Console.WriteLine("=".PadRight(60, '='));
        Console.WriteLine();

        // Task 1a: Preimage-Angriff
        Task1a_PreimageAttack();

        Console.WriteLine();

        // Task 1b: Brute-Force-Analyse für 32-bit Plaintext
        Task1b_BruteForceAnalysis();
    }

    static void Task1a_PreimageAttack()
    {
        Console.WriteLine("--- Task 1a: Preimage-Angriff ---");
        Console.WriteLine($"Ziel-Hash: {TargetHash:x8}");
        Console.WriteLine("Suche alphanumerisches Passwort...");
        Console.WriteLine();

        var stopwatch = Stopwatch.StartNew();
        long attempts = 0;
        string? found = null;

        // Suche Passwörter verschiedener Längen (1 bis 8 Zeichen)
        for (int length = 1; length <= 8 && found == null; length++)
        {
            Console.WriteLine($"Teste Länge {length}...");
            found = SearchPassword(length, ref attempts);
        }

        stopwatch.Stop();

        if (found != null)
        {
            Console.WriteLine();
            Console.WriteLine($"GEFUNDEN: \"{found}\"");
            Console.WriteLine($"Verifikation: BabySha(\"{found}\") = {BabySha.BabySha.HashToHex(found)}");
            Console.WriteLine($"Versuche: {attempts:N0}");
            Console.WriteLine($"Zeit: {stopwatch.ElapsedMilliseconds} ms");
        }
        else
        {
            Console.WriteLine("Kein Passwort gefunden!");
        }
    }

    static string? SearchPassword(int length, ref long attempts)
    {
        int[] indices = new int[length];
        char[] password = new char[length];
        int total = AlphaNumeric.Length;

        while (true)
        {
            // Baue Passwort aus aktuellen Indizes
            for (int i = 0; i < length; i++)
                password[i] = AlphaNumeric[indices[i]];

            string pwd = new string(password);
            attempts++;

            if (BabySha.BabySha.Hash(pwd) == TargetHash)
                return pwd;

            // Nächste Kombination
            int pos = length - 1;
            while (pos >= 0)
            {
                indices[pos]++;
                if (indices[pos] < total)
                    break;
                indices[pos] = 0;
                pos--;
            }

            if (pos < 0)
                break; // Alle Kombinationen dieser Länge erschöpft
        }

        return null;
    }

    static void Task1b_BruteForceAnalysis()
    {
        Console.WriteLine("--- Task 1b: Brute-Force-Analyse (32-bit Plaintext) ---");
        Console.WriteLine();

        // Theoretische Analyse
        Console.WriteLine("Theoretische Analyse:");
        Console.WriteLine("  - Keyspace: 2^32 = 4.294.967.296 mögliche 32-bit Werte");
        Console.WriteLine("  - Erwartete Versuche (Durchschnitt): 2^31 = 2.147.483.648");
        Console.WriteLine("  - Bei 50% Wahrscheinlichkeit nach ~2^31 Versuchen");
        Console.WriteLine();

        // Praktische Analyse: Brute-Force mit zufälligem Ziel-Hash
        Console.WriteLine("Praktische Analyse:");
        Console.WriteLine("Generiere zufälligen 32-bit Wert und suche Preimage...");

        var random = new Random();
        byte[] targetBytes = new byte[4];
        random.NextBytes(targetBytes);
        uint targetValue = BitConverter.ToUInt32(targetBytes, 0);
        uint targetHash = BabySha.BabySha.Hash(targetBytes);

        Console.WriteLine($"  Zufälliger Input: {targetValue:x8}");
        Console.WriteLine($"  Dessen Hash: {targetHash:x8}");
        Console.WriteLine();
        Console.WriteLine("Suche beliebigen 32-bit Wert mit gleichem Hash...");

        var stopwatch = Stopwatch.StartNew();
        long attempts = 0;
        byte[] testBytes = new byte[4];

        for (uint i = 0; i < uint.MaxValue; i++)
        {
            testBytes[0] = (byte)(i & 0xFF);
            testBytes[1] = (byte)((i >> 8) & 0xFF);
            testBytes[2] = (byte)((i >> 16) & 0xFF);
            testBytes[3] = (byte)((i >> 24) & 0xFF);

            attempts++;

            if (BabySha.BabySha.Hash(testBytes) == targetHash)
            {
                stopwatch.Stop();
                uint foundValue = BitConverter.ToUInt32(testBytes, 0);

                Console.WriteLine();
                Console.WriteLine($"GEFUNDEN nach {attempts:N0} Versuchen!");
                Console.WriteLine($"  Gefundener Input: {foundValue:x8}");
                Console.WriteLine($"  Dessen Hash: {BabySha.BabySha.HashToHex(testBytes)}");
                Console.WriteLine($"  Zeit: {stopwatch.Elapsed.TotalSeconds:F2} Sekunden");
                Console.WriteLine($"  Hashes/Sekunde: {attempts / stopwatch.Elapsed.TotalSeconds:N0}");
                Console.WriteLine();
                Console.WriteLine($"Vergleich zur Theorie:");
                Console.WriteLine($"  Erwartet: ~2.147.483.648 Versuche");
                Console.WriteLine($"  Tatsächlich: {attempts:N0} Versuche");
                Console.WriteLine($"  Verhältnis: {(double)attempts / 2147483648.0:P2}");
                return;
            }

            // Fortschritt alle 100 Millionen
            if (attempts % 100_000_000 == 0)
            {
                Console.WriteLine($"  {attempts / 1_000_000} Mio Versuche... ({stopwatch.Elapsed.TotalSeconds:F1}s)");
            }
        }

        Console.WriteLine("Suche abgeschlossen ohne Fund (unwahrscheinlich!)");
    }
}
