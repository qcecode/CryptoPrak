using Prak02;

// Vereinfachte Demo ohne Datei-I/O: Alle Werte als Strings im Code.
// Hinweis: Erwartet Hex-Strings (wie im Python-Beispiel), z. B. 4 Hex-Zeichen = 2 Bytes.

// Keys (hex) und Plaintext (hex) direkt hier setzen
string key1 = "16cf";
string key2 = "2ea3";
string plaintext = "4320";

Console.WriteLine("DES1 key: " + key1);
Console.WriteLine("DES2 key: " + key2);
Console.WriteLine("plaintext: " + plaintext);

// Zwei Instanzen wie in python/des_toy.py: encrypt -> encrypt -> decrypt -> decrypt
var des1 = new ToyDes();
var des2 = new ToyDes();

des1.SetKey(key1);
des2.SetKey(key2);

des1.SetDirect(true);
string enc1 = des1.Cipher(plaintext);
Console.WriteLine("DES1 encryption (cipher1): " + enc1);

des2.SetDirect(true);
string enc2 = des2.Cipher(enc1);
Console.WriteLine("DES2 encryption (ciphertext): " + enc2);

// Für Klarheit: "ciphertext" bezeichnet hier das Ergebnis nach zwei Verschlüsselungen
string ciphertext = enc2;

des2.SetDirect(false);
string dec2 = des2.Cipher(ciphertext);
Console.WriteLine("DES2 decryption: " + dec2);

des1.SetDirect(false);
string dec1 = des1.Cipher(dec2);
Console.WriteLine("DES1 decryption (plaintext again): " + dec1);

Console.WriteLine();
Console.WriteLine("-- Summary --");
Console.WriteLine($"key1={key1}");
Console.WriteLine($"key2={key2}");
Console.WriteLine($"plaintext={plaintext}");
Console.WriteLine($"enc1={enc1}");
Console.WriteLine($"ciphertext={ciphertext}");
Console.WriteLine($"dec2={dec2}");
Console.WriteLine($"dec1={dec1}");
