using System.Text;
using Prak02;

// Vereinfachte Demo ohne Datei-I/O: Alle Werte als Strings im Code.
// Hinweis: Erwartet Hex-Strings (wie im Python-Beispiel), z. B. 4 Hex-Zeichen = 2 Bytes.

// Keys (hex) und Plaintext (hex) direkt hier setzen
const string key1 = "16cf";
const string key2 = "2ea3";
string plaintextUtf8 = "Hi there What are we doing today";
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

var lol = new KnownPlaintextAndCiphertext { Plaintext = plaintext, Ciphertext = ciphertext };
var lolliste = new List<KnownPlaintextAndCiphertext> { lol };
MeetInTheMiddle(lolliste);
// Meet in the middle attack

static void MeetInTheMiddle(List<KnownPlaintextAndCiphertext> knownPlaintextAndCiphertexts)
{
    // Init
    var des1 = new ToyDes();
    des1.SetDirect(true);
    var des2 = new ToyDes();    
    des2.SetDirect(false);
    
    // Contains all possible ciphertexts (x) for a given plaintext as key and matching keys as values
    Dictionary<string, List<string>> multiDict = new Dictionary<string, List<string>>();
    HashSet<string> possibleKeysK1 = new HashSet<string>();
    HashSet<string> possibleKeysK2 = new HashSet<string>();
    
    for (int i = 0; i <= 0xFFFF; i++)
    {
        var hexKey = i.ToString("X4"); // 4-stellig: "0000" bis "FFFF"
        des1.SetKey(hexKey);
        var x = des1.Cipher(knownPlaintextAndCiphertexts.First().Plaintext);; // cypher after des1
        if (!multiDict.ContainsKey(x))
        {
            multiDict[x] = new List<string>();
        }
        multiDict[x].Add(hexKey);
    }

    for (int i = 0; i <= 0xFFFF; i++)
    {
        var hexKey = i.ToString("x4");
        des2.SetKey(hexKey);
        var x = des2.Cipher(knownPlaintextAndCiphertexts.First().Ciphertext);
        if (multiDict.ContainsKey(x))
        {
            possibleKeysK1.UnionWith(multiDict[x]);
            possibleKeysK2.Add(hexKey);
            multiDict.Remove(x);
        }
    }
    
    Console.WriteLine($"Possible keys K1: {string.Join(", ", possibleKeysK1)}");
    Console.WriteLine($"Possible keys K2: {string.Join(", ", possibleKeysK2)}");
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
