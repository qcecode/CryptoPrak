var inputPath = Path.Combine("/home/dev/repos/CryptoPrak/src/Prak01/Data/input.txt");
var outputPath = Path.Combine("/home/dev/repos/CryptoPrak/src/Prak01/Data/output.txt");

var content = File.ReadAllText(inputPath).Trim();
Console.WriteLine("content: " + content);

// Fixed permutation key e
int[] e = { 2, 4, 1, 5, 3 };

// Chunk, encrypt, and save ciphertext as one continuous string
var blocks = ChunkIntoBlocks(content, 5, 'x');
var cipherBlocks = new List<string>(blocks.Count);
foreach (var b in blocks)
    cipherBlocks.Add(ApplyPermutation(b, e));

var ciphertext = string.Concat(cipherBlocks);
Console.WriteLine("ciphertext: " + ciphertext);
File.WriteAllText(outputPath, ciphertext);

// Decrypt using inverse permutation and print plaintext
var d = InvertPermutation(e);
Console.WriteLine("d: " + string.Join("", d));
var decryptedBlocks = new List<string>(cipherBlocks.Count);
foreach (var cb in cipherBlocks)
    decryptedBlocks.Add(ApplyPermutation(cb, d));

var decryptedJoined = string.Concat(decryptedBlocks);
var plaintext = decryptedJoined.Substring(0, content.Length);
Console.WriteLine("plaintext: "  + plaintext);

// --- helpers ---
static List<string> ChunkIntoBlocks(string s, int size, char padChar)
{
    var blocks = new List<string>(capacity: (s.Length + size - 1) / size);
    for (int i = 0; i < s.Length; i += size)
    {
        int take = Math.Min(size, s.Length - i);
        var block = s.Substring(i, take);
        if (block.Length < size)
            block = block.PadRight(size, padChar);
        blocks.Add(block);
    }
    return blocks;
}

static string ApplyPermutation(string block, int[] perm)
{
    var output = new char[block.Length];
    for (int i = 0; i < perm.Length; i++)
    {
        int src = perm[i] - 1; // 1-based to 0-based
        output[i] = block[src];
    }
    return new string(output);
}

static int[] InvertPermutation(int[] e)
{
    var n = e.Length;
    var d = new int[n];
    for (int i = 0; i < n; i++)
    {
        int v = e[i];      // 1..n
        d[v - 1] = i + 1;  // place inverse (1-based)
    }
    return d;
}