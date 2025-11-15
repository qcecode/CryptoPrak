using System.Text;

namespace Prak02.Utils
{
    public static class HexConverter
    {
        public static string ToHex(string text)
        {
            if (text is null)
                throw new ArgumentNullException(nameof(text));

            return Convert.ToHexString(Encoding.UTF8.GetBytes(text)).ToLowerInvariant();
        }

        public static string FromHex(string hex)
        {
            if (hex is null)
                throw new ArgumentNullException(nameof(hex));

            return Encoding.UTF8.GetString(Convert.FromHexString(hex));
        }
    }
}