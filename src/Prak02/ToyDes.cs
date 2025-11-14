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

        public string Cipher(string hex)
        {
            if (hex is null) throw new ArgumentNullException(nameof(hex));
            var buffer = Convert.FromHexString(hex);
            var len = buffer.Length;
            var ret = NativeMethods.toy_des_cipher(_handle, buffer, ref len, buffer.Length);
            if (ret != 0)
                throw new InvalidOperationException($"toy_des_cipher failed with error {ret}");
            // Buffer wird in-place modifiziert; Länge bleibt gleich
            return Convert.ToHexString(buffer).ToLowerInvariant();
        }

        public void Dispose()
        {
            // Keine explizite Free-Funktion in libdestoy.h, daher nichts zu tun.
            // Handle lebt bis Prozessende.
        }
    }
}
