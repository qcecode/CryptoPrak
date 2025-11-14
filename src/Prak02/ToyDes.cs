using System;
using System.Runtime.InteropServices;

namespace Prak02
{
    internal static class NativeMethods
    {
        private const string LibName = "libdestoy"; // lädt libdestoy.so auf Linux

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr create_toy_des();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int toy_des_set_key(IntPtr cipher, byte[] key, int len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int toy_des_set_direct(IntPtr cipher, int dir);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int toy_des_cipher(IntPtr cipher, byte[] buffer, ref int len, int buffer_len);
    }

    public sealed class ToyDes : IDisposable
    {
        private readonly IntPtr _handle;

        public ToyDes()
        {
            _handle = NativeMethods.create_toy_des();
            if (_handle == IntPtr.Zero)
                throw new InvalidOperationException("create_toy_des() returned null handle");
        }

        public void SetKey(string hex)
        {
            if (hex is null) throw new ArgumentNullException(nameof(hex));
            var key = Convert.FromHexString(hex);
            var ret = NativeMethods.toy_des_set_key(_handle, key, key.Length);
            if (ret != 0)
                throw new InvalidOperationException($"toy_des_set_key failed with error {ret}");
        }

        public void SetDirect(bool direct)
        {
            var ret = NativeMethods.toy_des_set_direct(_handle, direct ? 1 : 0);
            if (ret != 0)
                throw new InvalidOperationException($"toy_des_set_direct failed with error {ret}");
        }

        /// <summary>
        /// Verschlüsselt/entschlüsselt einen Hex-String beliebiger Länge (Vielfaches von 4 Hex-Zeichen).
        /// Intern wird blockweise (2 Bytes = 4 Hex) gearbeitet, damit die native Funktion zuverlässig funktioniert.
        /// </summary>
        public string Cipher(string hex)
        {
            if (hex is null) throw new ArgumentNullException(nameof(hex));
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex-String muss eine gerade Anzahl an Zeichen haben (volle Bytes)");
            if (hex.Length % 4 != 0)
                throw new ArgumentException("Hex-String-Länge muss Vielfaches von 4 sein (2-Byte-Blöcke)");

            // Schneller Pfad: einzelner Block
            if (hex.Length == 4)
                return CipherBlock(hex);

            // Mehrere Blöcke: jeweils 4 Hex-Zeichen verarbeiten
            var sb = new System.Text.StringBuilder(hex.Length);
            for (int i = 0; i < hex.Length; i += 4)
            {
                var block = hex.Substring(i, 4);
                sb.Append(CipherBlock(block));
            }
            return sb.ToString();
        }

        private string CipherBlock(string hex4)
        {
            // Erwartet genau 1 Block = 2 Bytes = 4 Hex-Zeichen
            if (hex4 is null || hex4.Length != 4)
                throw new ArgumentException("hex4 muss genau 4 Hex-Zeichen (1 Block) enthalten", nameof(hex4));

            var buffer = Convert.FromHexString(hex4);
            var len = buffer.Length; // = 2
            var ret = NativeMethods.toy_des_cipher(_handle, buffer, ref len, buffer.Length);
            if (ret != 0)
                throw new InvalidOperationException($"toy_des_cipher failed with error {ret}");
            return Convert.ToHexString(buffer).ToLowerInvariant();
        }

        public void Dispose()
        {
            // Keine explizite Free-Funktion in libdestoy.h, daher nichts zu tun.
            // Handle lebt bis Prozessende.
        }
    }
}
