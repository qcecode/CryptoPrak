using System.Text;
using Prak02;

// Vereinfachte Demo ohne Datei-I/O: Alle Werte als Strings im Code.
// Hinweis: Erwartet Hex-Strings (wie im Python-Beispiel), z. B. 4 Hex-Zeichen = 2 Bytes.

// Keys (hex) und Plaintext (hex) direkt hier setzen
const string key1 = "16cf";
const string key2 = "2ea3";
string plaintextUtf8 = "Hello World!";
string plaintext = ToHex(plaintextUtf8);


Console.WriteLine("DES1 key: " + key1);
Console.WriteLine("DES2 key: " + key2);
Console.WriteLine("plaintext: " + plaintext);

// Zwei Instanzen wie in python/des_toy.py: encrypt -> encrypt -> decrypt -> decrypt
var des1 = new ToyDes();
var des2 = new ToyDes();

des1.SetKey(key1);
des2.SetKey(key2);

// Der Wrapper (ToyDes.Cipher) verarbeitet intern blockweise beliebig lange Hex-Strings

des1.SetDirect(true);
string enc1 = des1.Cipher(plaintext);
Console.WriteLine("DES1 encryption (cipher1): " + enc1);

des2.SetDirect(true);
string ciphertext = des2.Cipher(enc1);
Console.WriteLine("DES2 encryption (ciphertext): " + ciphertext);

des2.SetDirect(false);
string dec2 = des2.Cipher(ciphertext);
Console.WriteLine("DES2 decryption: " + dec2);

des1.SetDirect(false);
string dec1 = des1.Cipher(dec2);
Console.WriteLine("DES1 decryption (plaintext again): " + dec1);

string dec1Utf8 = FromHex(dec1);

Console.WriteLine();
Console.WriteLine("-- Summary --");
Console.WriteLine($"key1={key1}");
Console.WriteLine($"key2={key2}");
Console.WriteLine($"plaintextUtf8={plaintextUtf8}");
Console.WriteLine($"plaintext={plaintext}");
Console.WriteLine($"enc1={enc1}");
Console.WriteLine($"ciphertext={ciphertext}");
Console.WriteLine($"dec2={dec2}");
Console.WriteLine($"dec1={dec1}");
Console.WriteLine($"dec1_utf8={dec1Utf8}");

// Meet in the middle attack

des1.SetDirect(true);
des2.SetDirect(true);

string plaintext1Utf8 = "Wir gehen rein";
string plaintext1 = ToHex(plaintext1Utf8);
string ciphertext1 = des2.Cipher(des1.Cipher(plaintext1));

string plaintext2Utf8 = "Hello World!";
string plaintext2 = ToHex(plaintext2Utf8);
string ciphertext2 = des2.Cipher(des1.Cipher(plaintext2));


var knownPlaintextAndCiphertext1 = new KnownPlaintextAndCiphertext { Plaintext = plaintext1, Ciphertext = ciphertext1 };
var knownPlaintextAndCiphertext2 = new KnownPlaintextAndCiphertext { Plaintext = plaintext2, Ciphertext = ciphertext2 };

var lol = new KnownPlaintextAndCiphertext { Plaintext = plaintext, Ciphertext = ciphertext };
List<string> lolList = new List<string>();
for (int i = 0; i <= 0xFFFF; i++)
{
    string hexKey = i.ToString("X4"); // 4-stellig: "0000" bis "FFFF"
    lolList.Add(hexKey);
}
Console.WriteLine("\n=== Meet-in-the-Middle Attack ===");
Console.WriteLine($"Searching for key1={key1.ToUpper()}, key2={key2.ToUpper()}");
Console.WriteLine($"\nRound 1 with plaintext1='{plaintext1Utf8}':");
Console.WriteLine($"  Plaintext:  {plaintext1}");
Console.WriteLine($"  Ciphertext: {ciphertext1}");
var round1Pairs = MeetInTheMiddle(knownPlaintextAndCiphertext1, lolList, lolList);

// Extrahiere unique K1 und K2 aus Round 1 für Round 2
var candidateK1 = round1Pairs.Select(p => p.K1).Distinct().ToList();
var candidateK2 = round1Pairs.Select(p => p.K2).Distinct().ToList();

Console.WriteLine($"\nRound 2 with plaintext2='{plaintext2Utf8}':");
Console.WriteLine($"  Plaintext:  {plaintext2}");
Console.WriteLine($"  Ciphertext: {ciphertext2}");
var finalResult = MeetInTheMiddle(knownPlaintextAndCiphertext2, candidateK1, candidateK2);

Console.WriteLine($"\n=== Final Result ===");
var sortedPairs = finalResult.OrderBy(p => p.K1).ThenBy(p => p.K2).ToList();

Console.WriteLine($"Found {finalResult.Count} unique key pair(s):");
foreach (var pair in sortedPairs)
{
    string match = (pair.K1.Equals(key1.ToUpper()) && pair.K2.Equals(key2.ToUpper())) ? " ← CORRECT!" : "";
    Console.WriteLine($"  K1={pair.K1}, K2={pair.K2}{match}");
}


HashSet<(string K1, string K2)> MeetInTheMiddle(
    KnownPlaintextAndCiphertext knownPlaintextAndCiphertexts,
    List<string> possibleKeysK1,
    List<string> possibleKeysK2)
{
    // Init
    var des1 = new ToyDes();
    des1.SetDirect(true);
    var des2 = new ToyDes();
    des2.SetDirect(false);

    // Dictionary: Zwischenwert -> Liste von K1-Schlüsseln, die zu diesem Zwischenwert führen
    var intermediateToK1 = new Dictionary<string, List<string>>();

    // HashSet für gefundene Schlüsselpaare - automatisch ohne Duplikate!
    var validKeyPairs = new HashSet<(string K1, string K2)>();

    // Phase 1: Verschlüssle Plaintext mit allen K1 und speichere Zwischenwerte
    foreach (var k1 in possibleKeysK1)
    {
        des1.SetKey(k1);
        var intermediate = des1.Cipher(knownPlaintextAndCiphertexts.Plaintext);

        if (!intermediateToK1.ContainsKey(intermediate))
        {
            intermediateToK1[intermediate] = new List<string>();
        }
        intermediateToK1[intermediate].Add(k1);
    }

    // Phase 2: Entschlüssle Ciphertext mit allen K2 und suche Matches
    foreach (var k2 in possibleKeysK2)
    {
        des2.SetKey(k2);
        var intermediate = des2.Cipher(knownPlaintextAndCiphertexts.Ciphertext);

        if (intermediateToK1.ContainsKey(intermediate))
        {
            // Match gefunden! Alle K1-Schlüssel zu diesem Zwischenwert sind gültig
            foreach (var k1 in intermediateToK1[intermediate])
            {
                validKeyPairs.Add((k1, k2));
            }
        }
    }

    // Extrahiere unique K1 und K2 für Debug-Ausgabe
    var uniqueK1 = validKeyPairs.Select(p => p.K1).Distinct().OrderBy(k => k).ToList();
    var uniqueK2 = validKeyPairs.Select(p => p.K2).Distinct().OrderBy(k => k).ToList();

    Console.WriteLine($"Possible keys K1 ({uniqueK1.Count}): {string.Join(", ", uniqueK1)}");
    Console.WriteLine($"Possible keys K2 ({uniqueK2.Count}): {string.Join(", ", uniqueK2)}");
    Console.WriteLine($"Valid key pairs found: {validKeyPairs.Count}");

    return validKeyPairs;
}

// Helper 
// String zu Hex
static string ToHex(string text)
{
    return Convert.ToHexString(Encoding.UTF8.GetBytes(text));
}

// Hex zu String
static string FromHex(string hex)
{
    return Encoding.UTF8.GetString(Convert.FromHexString(hex));
}

public class KnownPlaintextAndCiphertext
{
    public required string Plaintext { get; set; }
    public required string Ciphertext { get; set; }
}