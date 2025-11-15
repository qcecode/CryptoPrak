using Prak02.Cryptography;
using Prak02.Models;
using Prak02.Utils;

namespace Prak02
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=".PadRight(70, '='));
            Console.WriteLine("Praktikum 2: Meet-in-the-Middle Attack on Double-DES");
            Console.WriteLine("=".PadRight(70, '='));
            Console.WriteLine();

            // Define the secret keys for Double-DES
            var secretKeys = new KeyPair { K1 = "16cf", K2 = "2ea3" };

            // Run double des demo
            var demoMessage = "Hello World!";
            DemonstrateDoubleDes(secretKeys, demoMessage);
            Console.WriteLine();

            // Run meet in the middle attack demo
            var testMessages = new List<string> { "Hello World!", "Goodbye World!" };
            var plaintextCipherTextPairs = CreateTestPairs(secretKeys, testMessages);
            PerformMeetInTheMiddleAttack(secretKeys, plaintextCipherTextPairs);
        }

        private static void DemonstrateDoubleDes(KeyPair keys, string stringToEncryptUtf8)
        {
            Console.WriteLine("--- Double-DES Encryption/Decryption Demo ---");
            Console.WriteLine();

            var doubleDes = new DoubleDes();
            doubleDes.SetKeys(keys);

            // Test data
            string plaintext = HexConverter.ToHex(stringToEncryptUtf8);

            Console.WriteLine($"Secret Keys: K1={keys.K1.ToUpper()}, K2={keys.K2.ToUpper()}");
            Console.WriteLine($"Plaintext (UTF-8): {stringToEncryptUtf8}");
            Console.WriteLine($"Plaintext (Hex):   {plaintext.ToUpperInvariant()}");
            Console.WriteLine();

            // Encrypt with intermediate value
            var ciphertext = doubleDes.EncryptWithIntermediate(plaintext, out var intermediate);

            Console.WriteLine("Encryption Process:");
            Console.WriteLine($"  Step 1 - DES1(P, K1):     {intermediate.ToUpperInvariant()}");
            Console.WriteLine($"  Step 2 - DES2(Mid, K2):   {ciphertext.ToUpperInvariant()}");
            Console.WriteLine();

            // Decrypt
            var decrypted = doubleDes.Decrypt(ciphertext);
            var decryptedUtf8 = HexConverter.FromHex(decrypted);

            Console.WriteLine("Decryption Process:");
            Console.WriteLine($"  Ciphertext:               {ciphertext.ToUpperInvariant()}");
            Console.WriteLine($"  Decrypted (Hex):          {decrypted.ToUpperInvariant()}");
            Console.WriteLine($"  Decrypted (UTF-8):        {decryptedUtf8}");
            Console.WriteLine();

            // Verify
            bool success = decryptedUtf8 == stringToEncryptUtf8;
            Console.WriteLine($"Verification: {(success ? "✓ SUCCESS" : "✗ FAILED")}");
        }

        private static void PerformMeetInTheMiddleAttack(KeyPair secretKeys,
            List<(PlaintextCiphertextPair pair, string utf8)> pairs)
        {
            Console.WriteLine("--- Meet-in-the-Middle Attack ---");
            Console.WriteLine();

            Console.WriteLine($"Attack Goal: Recover K1={secretKeys.K1.ToUpper()}, K2={secretKeys.K2.ToUpper()}");
            Console.WriteLine($"Known Pairs: {pairs.Count}");
            foreach (var (pair, utf8) in pairs)
            {
                Console.WriteLine($"  - '{utf8}'");
                Console.WriteLine($"    P: {pair.Plaintext.ToUpperInvariant()}");
                Console.WriteLine($"    C: {pair.Ciphertext.ToUpperInvariant()}");
            }

            Console.WriteLine();

            // Generate all possible keys (16-bit keyspace = 65536 keys)
            var allPossibleKeys = MeetInTheMiddleAttack.GenerateAllPossibleKeys(16);
            Console.WriteLine($"Keyspace: {allPossibleKeys.Count:N0} possible keys (2^16)");
            Console.WriteLine();

            // Create attack instance with progress reporting
            var progress = new Progress<AttackProgress>(ReportProgress);
            var attack = new MeetInTheMiddleAttack(progress);

            // Perform multi-round attack
            var onlyPairs = pairs.Select(p => p.pair).ToList();
            var recoveredKeys = attack.MultiRoundAttack(onlyPairs, allPossibleKeys);

            // Display results
            Console.WriteLine();
            Console.WriteLine("=== Attack Results ===");
            Console.WriteLine($"Found {recoveredKeys.Count} valid key pair(s):");
            Console.WriteLine();

            var sortedKeys = recoveredKeys.OrderBy(p => p.K1).ThenBy(p => p.K2).ToList();
            foreach (var keyPair in sortedKeys)
            {
                bool isCorrect = keyPair.K1.Equals(secretKeys.K1, StringComparison.OrdinalIgnoreCase) &&
                                 keyPair.K2.Equals(secretKeys.K2, StringComparison.OrdinalIgnoreCase);

                string marker = isCorrect ? " ← CORRECT!" : "";
                Console.WriteLine($"  {keyPair}{marker}");
            }

            Console.WriteLine();

            // Verify the attack succeeded
            if (recoveredKeys.Any(k =>
                    k.K1.Equals(secretKeys.K1, StringComparison.OrdinalIgnoreCase) &&
                    k.K2.Equals(secretKeys.K2, StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine("✓ Attack successful! Secret keys recovered.");
            }
            else
            {
                Console.WriteLine("✗ Attack failed. Secret keys not found.");
            }
        }

        private static List<(PlaintextCiphertextPair pair, string utf8)> CreateTestPairs(KeyPair keys,
            List<string> testMessages)
        {
            var doubleDes = new DoubleDes();
            doubleDes.SetKeys(keys);

            var pairs = new List<(PlaintextCiphertextPair, string)>();

            foreach (var message in testMessages)
            {
                var plaintext = HexConverter.ToHex(message);
                var ciphertext = doubleDes.Encrypt(plaintext);

                pairs.Add((new PlaintextCiphertextPair
                {
                    Plaintext = plaintext,
                    Ciphertext = ciphertext
                }, message));
            }

            return pairs;
        }

        private static void ReportProgress(AttackProgress progress)
        {
            if (progress.Phase == AttackPhase.RoundStarting ||
                progress.Phase == AttackPhase.Phase1Starting ||
                progress.Phase == AttackPhase.Phase2Starting ||
                progress.Phase == AttackPhase.RoundComplete)
            {
                Console.WriteLine(progress.Message);
            }
        }
    }
}