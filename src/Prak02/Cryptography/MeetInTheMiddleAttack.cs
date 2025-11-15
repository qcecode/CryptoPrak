using Prak02.Models;

namespace Prak02.Cryptography
{
    public class MeetInTheMiddleAttack
    {
        private readonly IProgress<AttackProgress>? _progress;

        public MeetInTheMiddleAttack(IProgress<AttackProgress>? progress = null)
        {
            _progress = progress;
        }

        public HashSet<KeyPair> Attack(
            PlaintextCiphertextPair pair,
            IReadOnlyList<string> possibleK1,
            IReadOnlyList<string> possibleK2)
        {
            if (pair is null)
                throw new ArgumentNullException(nameof(pair));
            if (possibleK1 is null)
                throw new ArgumentNullException(nameof(possibleK1));
            if (possibleK2 is null)
                throw new ArgumentNullException(nameof(possibleK2));

            _progress?.Report(new AttackProgress
            {
                Phase = AttackPhase.Phase1Starting,
                Message = $"Starting Phase 1: Testing {possibleK1.Count:N0} possible K1 keys"
            });

            var intermediateToK1 = BuildEncryptionTable(pair.Plaintext, possibleK1);

            _progress?.Report(new AttackProgress
            {
                Phase = AttackPhase.Phase1Complete,
                Message = $"Phase 1 complete: Found {intermediateToK1.Count:N0} unique intermediate values"
            });

            _progress?.Report(new AttackProgress
            {
                Phase = AttackPhase.Phase2Starting,
                Message = $"Starting Phase 2: Testing {possibleK2.Count:N0} possible K2 keys"
            });

            var validKeyPairs = FindMatchingKeys(pair.Ciphertext, possibleK2, intermediateToK1);

            _progress?.Report(new AttackProgress
            {
                Phase = AttackPhase.Phase2Complete,
                Message = $"Phase 2 complete: Found {validKeyPairs.Count:N0} valid key pairs"
            });

            return validKeyPairs;
        }

        public HashSet<KeyPair> MultiRoundAttack(
            IReadOnlyList<PlaintextCiphertextPair> pairs,
            IReadOnlyList<string> allPossibleKeys)
        {
            if (pairs is null || pairs.Count == 0)
                throw new ArgumentException("At least one plaintext-ciphertext pair is required.", nameof(pairs));
            if (allPossibleKeys is null)
                throw new ArgumentNullException(nameof(allPossibleKeys));

            // First round: use all possible keys
            _progress?.Report(new AttackProgress
            {
                Round = 1,
                Phase = AttackPhase.RoundStarting,
                Message = $"Round 1: Full keyspace search ({allPossibleKeys.Count:N0} keys)"
            });

            var candidateKeys = Attack(pairs[0], allPossibleKeys, allPossibleKeys);

            _progress?.Report(new AttackProgress
            {
                Round = 1,
                Phase = AttackPhase.RoundComplete,
                Message = $"Round 1 complete: {candidateKeys.Count:N0} candidate key pairs found"
            });

            if (pairs.Count == 1)
                return candidateKeys;

            // Extract unique K1 and K2 candidates from first round
            var candidateK1 = candidateKeys.Select(p => p.K1).Distinct().ToList();
            var candidateK2 = candidateKeys.Select(p => p.K2).Distinct().ToList();

            // Subsequent rounds: use narrowed down candidates
            for (int i = 1; i < pairs.Count; i++)
            {
                _progress?.Report(new AttackProgress
                {
                    Round = i + 1,
                    Phase = AttackPhase.RoundStarting,
                    Message =
                        $"Round {i + 1}: Refining search with {candidateK1.Count:N0} K1 and {candidateK2.Count:N0} K2 candidates"
                });

                candidateKeys = Attack(pairs[i], candidateK1, candidateK2);

                _progress?.Report(new AttackProgress
                {
                    Round = i + 1,
                    Phase = AttackPhase.RoundComplete,
                    Message = $"Round {i + 1} complete: {candidateKeys.Count:N0} candidate key pairs remaining"
                });

                if (candidateKeys.Count == 0)
                    break;

                // Update candidates for next round
                candidateK1 = candidateKeys.Select(p => p.K1).Distinct().ToList();
                candidateK2 = candidateKeys.Select(p => p.K2).Distinct().ToList();
            }

            return candidateKeys;
        }

        private Dictionary<string, List<string>> BuildEncryptionTable(
            string plaintext,
            IReadOnlyList<string> possibleK1)
        {
            var intermediateToK1 = new Dictionary<string, List<string>>();

            using var des1 = new ToyDes();
            des1.SetDirect(true);

            int processed = 0;
            foreach (var k1 in possibleK1)
            {
                des1.SetKey(k1);
                var intermediate = des1.Cipher(plaintext);

                if (!intermediateToK1.ContainsKey(intermediate))
                {
                    intermediateToK1[intermediate] = new List<string>();
                }

                intermediateToK1[intermediate].Add(k1);

                processed++;
                if (processed % 10000 == 0)
                {
                    _progress?.Report(new AttackProgress
                    {
                        Phase = AttackPhase.Phase1InProgress,
                        ProcessedKeys = processed,
                        TotalKeys = possibleK1.Count,
                        Message = $"Phase 1: Processed {processed:N0}/{possibleK1.Count:N0} keys"
                    });
                }
            }

            return intermediateToK1;
        }

        private HashSet<KeyPair> FindMatchingKeys(
            string ciphertext,
            IReadOnlyList<string> possibleK2,
            Dictionary<string, List<string>> intermediateToK1)
        {
            var validKeyPairs = new HashSet<KeyPair>();

            using var des2 = new ToyDes();
            des2.SetDirect(false); // Decrypt mode

            int processed = 0;
            foreach (var k2 in possibleK2)
            {
                des2.SetKey(k2);
                var intermediate = des2.Cipher(ciphertext);

                if (intermediateToK1.TryGetValue(intermediate, out var k1List))
                {
                    // Match found! All K1 keys that produce this intermediate are valid
                    foreach (var k1 in k1List)
                    {
                        validKeyPairs.Add(new KeyPair { K1 = k1, K2 = k2 });
                    }
                }

                processed++;
                if (processed % 10000 == 0)
                {
                    _progress?.Report(new AttackProgress
                    {
                        Phase = AttackPhase.Phase2InProgress,
                        ProcessedKeys = processed,
                        TotalKeys = possibleK2.Count,
                        Message = $"Phase 2: Processed {processed:N0}/{possibleK2.Count:N0} keys"
                    });
                }
            }

            return validKeyPairs;
        }

        public static List<string> GenerateAllPossibleKeys(int keySizeBits)
        {
            if (keySizeBits <= 0 || keySizeBits > 32)
                throw new ArgumentOutOfRangeException(nameof(keySizeBits), "Key size must be between 1 and 32 bits.");

            int maxValue = (1 << keySizeBits) - 1;
            int hexDigits = (keySizeBits + 3) / 4; // Round up to next hex digit
            var keys = new List<string>(maxValue + 1);

            for (int i = 0; i <= maxValue; i++)
            {
                keys.Add(i.ToString($"X{hexDigits}"));
            }

            return keys;
        }
    }

    public enum AttackPhase
    {
        RoundStarting,
        Phase1Starting,
        Phase1InProgress,
        Phase1Complete,
        Phase2Starting,
        Phase2InProgress,
        Phase2Complete,
        RoundComplete
    }

    public class AttackProgress
    {
        public int Round { get; set; }
        public AttackPhase Phase { get; set; }
        public int ProcessedKeys { get; set; }
        public int TotalKeys { get; set; }
        public string Message { get; set; } = string.Empty;

        public double ProgressPercentage =>
            TotalKeys > 0 ? (double)ProcessedKeys / TotalKeys * 100 : 0;
    }
}