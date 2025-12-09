using System.Numerics;
using Prak03;

Console.WriteLine("Starte einfache Tests für Prak03.Program.IntegerCeilingSqrt ...");

void Check(BigInteger input, BigInteger expected)
{
    var actual = Prak03.Program.IntegerCeilingSqrt(input);
    if (actual != expected)
    {
        Console.WriteLine($"FEHLER: sqrt_ceil({input}) -> {actual}, erwartet {expected}");
        Environment.ExitCode = 1;
    }
    else
    {
        Console.WriteLine($"OK: sqrt_ceil({input}) = {actual}");
    }
}

// Ein paar grundlegende Fälle
Check(0, 0);
Check(1, 1);
Check(2, 2);   // ceil(sqrt(2)) = 2
Check(3, 2);
Check(4, 2);
Check(15, 4);
Check(16, 4);
Check(17, 5);

// Größerer Wert (sanity check)
Check(10_000, 100);

if (Environment.ExitCode == 0)
{
    Console.WriteLine("Alle einfachen Tests bestanden.");
}
