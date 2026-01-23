using System.Runtime.InteropServices;
using System.Text;

namespace Prak04.BabySha;

internal static class NativeMethods
{
    private const string LibName = "BabySha/libbabysha";

    // Erwartet: uint baby_sha_hash(const char* data, unsigned int dataLength)
    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint baby_sha_hash(byte[] data, uint dataLength);
}

public static class BabySha
{
    public static uint Hash(string text)
    {
        byte[] data = Encoding.ASCII.GetBytes(text);
        return NativeMethods.baby_sha_hash(data, (uint)data.Length);
    }

    public static uint Hash(byte[] data)
    {
        return NativeMethods.baby_sha_hash(data, (uint)data.Length);
    }

    public static string HashToHex(string text)
    {
        return Hash(text).ToString("x8");
    }

    public static string HashToHex(byte[] data)
    {
        return Hash(data).ToString("x8");
    }
}
