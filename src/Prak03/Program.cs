using System.Numerics;

namespace Prak03;

public class Program
{
    // Original BSGS (optimal balance)
    static BigInteger? BabyStepGiantStep(BigInteger g, BigInteger h, BigInteger p)
    {
        var n = p - 1;
        var m = IntegerCeilingSqrt(n);
        return BabyStepGiantStepWithParameter(g, h, p, m);
    }

    // BSGS with space-time trade-off parameter
    // k_factor controls the trade-off:
    // - k_factor < 1: Use MORE space, LESS time (m larger)
    // - k_factor = 1: Balanced (standard BSGS)
    // - k_factor > 1: Use LESS space, MORE time (m smaller)
    static BigInteger? BabyStepGiantStepTradeoff(BigInteger g, BigInteger h, BigInteger p, double kFactor)
    {
        var n = p - 1;
        var mOptimal = IntegerCeilingSqrt(n);
        
        // Adjust m based on k_factor (convert to double first, then back to BigInteger)
        var m = BigInteger.Max(1, (BigInteger)((double)mOptimal / kFactor));
        
        Console.WriteLine($"Trade-off parameter k = {kFactor:F2}");
        Console.WriteLine($"Optimal m = {mOptimal}, Using m = {m}");
        Console.WriteLine($"Baby steps: {m}, Giant steps (max): {(n / m) + 1}");
        Console.WriteLine($"Space: O({m}), Time: O({m + (n / m)})");
        Console.WriteLine();
        
        return BabyStepGiantStepWithParameter(g, h, p, m);
    }

    // Core BSGS implementation with custom m
    static BigInteger? BabyStepGiantStepWithParameter(BigInteger g, BigInteger h, BigInteger p, BigInteger m)
    {
        // Precompute baby steps: g^j mod p for j in [0, m-1]
        var table = new Dictionary<BigInteger, BigInteger>(capacity: (int)BigInteger.Min(m, int.MaxValue));
        var gj = BigInteger.One;
        for (BigInteger j = 0; j < m; j++)
        {
            if (!table.ContainsKey(gj)) table[gj] = j;
            gj = BigInteger.Remainder(gj * g, p);
        }

        // Compute factor = g^{-m} mod p
        var factor = BigInteger.ModPow(g, m * (p - 2), p);
        
        // Iterate giant steps
        var gamma = h % p;
        var maxIterations = ((p - 1) / m) + 1;
        
        for (BigInteger i = 0; i < maxIterations; i++)
        {
            if (table.TryGetValue(gamma, out var j))
            {
                return i * m + j;
            }
            gamma = BigInteger.Remainder(gamma * factor, p);
        }

        return null;
    }
    
    public static BigInteger IntegerCeilingSqrt(BigInteger n)
    {
        if (n <= 0) return 0;
        var approx = (BigInteger)Math.Ceiling(Math.Sqrt((double)n));
    
        while ((approx - 1) * (approx - 1) >= n)
            approx--;
    
        while (approx * approx < n)
            approx++;
    
        return approx;
    }

    static void Main(string[] args)
    {
        Console.WriteLine("=".PadRight(70, '='));
        Console.WriteLine("Praktikum 3: Diskrete Logarithmen – Baby-Step Giant-Step");
        Console.WriteLine("=".PadRight(70, '='));
        Console.WriteLine();

        BigInteger p = BigInteger.Parse("6971096459");
        BigInteger g = new BigInteger(2);
        BigInteger h = BigInteger.Parse("4178319614");

        Console.WriteLine($"Given: p = {p}, g = {g}, h = {h}");
        Console.WriteLine($"Group order n = p - 1 = {p - 1}");
        Console.WriteLine();

        // Test different trade-offs
        Console.WriteLine("TEIL (a): Standard BSGS (optimal)");
        Console.WriteLine("-".PadRight(70, '-'));
        var start = DateTime.UtcNow;
        var x = BabyStepGiantStep(g, h, p);
        var elapsed = DateTime.UtcNow - start;
        
        if (x != null)
        {
            Console.WriteLine($"✓ Solution found: x = {x}");
            var verify = BigInteger.ModPow(g, x.Value, p);
            Console.WriteLine($"✓ Verification: 2^{x} ≡ {verify} (mod p)");
            Console.WriteLine($"✓ Time: {elapsed.TotalMilliseconds:F2} ms");
        }
        Console.WriteLine();

        Console.WriteLine("TEIL (c): Space-Time Trade-offs");
        Console.WriteLine("-".PadRight(70, '-'));
        
        // Test different k values
        double[] k_values = { 0.1, 0.5, 1.0, 2.0, 5.0 };
        
        foreach (var k in k_values)
        {
            start = DateTime.UtcNow;
            x = BabyStepGiantStepTradeoff(g, h, p, k);
            elapsed = DateTime.UtcNow - start;
            
            if (x != null)
            {
                Console.WriteLine($"✓ Solution: x = {x}, Time: {elapsed.TotalMilliseconds:F2} ms");
            }
            Console.WriteLine();
        }
    }
}