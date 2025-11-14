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
var tuple = MeetInTheMiddle(knownPlaintextAndCiphertext1, lolList, lolList);

Console.WriteLine($"\nRound 2 with plaintext2='{plaintext2Utf8}':");
Console.WriteLine($"  Plaintext:  {plaintext2}");
Console.WriteLine($"  Ciphertext: {ciphertext2}");
var finalResult = MeetInTheMiddle(knownPlaintextAndCiphertext2, tuple.K1, tuple.K2);

Console.WriteLine($"\n=== Final Result ===");
// Erstelle eindeutige Paare
var uniquePairs = finalResult.K1.Zip(finalResult.K2, (k1, k2) => (K1: k1, K2: k2))
    .Distinct()
    .OrderBy(p => p.K1)
    .ThenBy(p => p.K2)
    .ToList();

Console.WriteLine($"Found {uniquePairs.Count} unique key pair(s):");
foreach (var pair in uniquePairs)
{
    string match = (pair.K1.Equals(key1.ToUpper()) && pair.K2.Equals(key2.ToUpper())) ? " ← CORRECT!" : "";
    Console.WriteLine($"  K1={pair.K1}, K2={pair.K2}{match}");
}


(List<string> K1, List<string> K2) MeetInTheMiddle(KnownPlaintextAndCiphertext knownPlaintextAndCiphertexts, 
    List<string> possibleKeysK1, List<string> possibleKeysK2)
{
    // Init
    var des1 = new ToyDes();
    des1.SetDirect(true);
    var des2 = new ToyDes();
    des2.SetDirect(false);
    
    // locally stored
    Dictionary<string, List<string>> multiDict = new Dictionary<string, List<string>>();
    List<string> newPossibleKeysK1 = new List<string>();
    List<string> newPossibleKeysK2 = new List<string>();

    foreach (var key in possibleKeysK1)
    {
        des1.SetKey(key);
        var x = des1.Cipher(knownPlaintextAndCiphertexts.Plaintext);
        ; // cypher after des1
        if (!multiDict.ContainsKey(x))
        {
            multiDict[x] = new List<string>();
        }

        multiDict[x].Add(key);
    }

    foreach (var key in possibleKeysK2)
    {
        des2.SetKey(key);
        var x = des2.Cipher(knownPlaintextAndCiphertexts.Ciphertext);
        if (multiDict.ContainsKey(x))
        {
            // Wichtig: Füge K2 für JEDEN K1-Match hinzu
            foreach (var k1 in multiDict[x])
            {
                newPossibleKeysK1.Add(k1);
                newPossibleKeysK2.Add(key);
            }
            // NICHT entfernen - könnte mehrere K2 für gleichen Zwischenwert geben!
            // multiDict.Remove(x);
        }
    }
    
    // Dedupliziere die Listen, da mehrere Zwischenwerte zu gleichen Keys führen können
    var distinctK1 = newPossibleKeysK1.Distinct().ToList();
    var distinctK2 = newPossibleKeysK2.Distinct().ToList();

    Console.WriteLine($"Possible keys K1 ({distinctK1.Count}): {string.Join(", ", distinctK1)}");
    Console.WriteLine($"Possible keys K2 ({distinctK2.Count}): {string.Join(", ", distinctK2)}");
    Console.WriteLine($"Total combinations to test: {distinctK1.Count} × {distinctK2.Count} = {distinctK1.Count * distinctK2.Count}");

    return (distinctK1, distinctK2);
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