namespace Prak02.Models
{
    public record KeyPair
    {
        public required string K1 { get; init; }

        public required string K2 { get; init; }

        public override string ToString() => $"(K1={K1}, K2={K2})";
    }
}