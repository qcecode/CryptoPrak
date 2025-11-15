using Prak02.Models;

namespace Prak02.Cryptography
{
    public class DoubleDes
    {
        private readonly ToyDes _des1;
        private readonly ToyDes _des2;
        private KeyPair? _keyPair;


        public DoubleDes()
        {
            _des1 = new ToyDes();
            _des2 = new ToyDes();
        }

        public void SetKeys(string key1, string key2)
        {
            if (key1 is null)
                throw new ArgumentNullException(nameof(key1));
            if (key2 is null)
                throw new ArgumentNullException(nameof(key2));

            _des1.SetKey(key1);
            _des2.SetKey(key2);
            _keyPair = new KeyPair { K1 = key1.ToUpperInvariant(), K2 = key2.ToUpperInvariant() };
        }

        public void SetKeys(KeyPair keyPair)
        {
            if (keyPair is null)
                throw new ArgumentNullException(nameof(keyPair));

            SetKeys(keyPair.K1, keyPair.K2);
        }

        public string Encrypt(string plaintext)
        {
            if (_keyPair is null)
                throw new InvalidOperationException("Keys must be set before encryption. Call SetKeys first.");

            if (plaintext is null)
                throw new ArgumentNullException(nameof(plaintext));

            _des1.SetDirect(true);
            _des2.SetDirect(true);

            var intermediate = _des1.Cipher(plaintext);
            var ciphertext = _des2.Cipher(intermediate);

            return ciphertext;
        }

        public string Decrypt(string ciphertext)
        {
            if (_keyPair is null)
                throw new InvalidOperationException("Keys must be set before decryption. Call SetKeys first.");

            if (ciphertext is null)
                throw new ArgumentNullException(nameof(ciphertext));

            _des2.SetDirect(false);
            _des1.SetDirect(false);

            var intermediate = _des2.Cipher(ciphertext);
            var plaintext = _des1.Cipher(intermediate);

            return plaintext;
        }

        public string EncryptWithIntermediate(string plaintext, out string intermediate)
        {
            if (_keyPair is null)
                throw new InvalidOperationException("Keys must be set before encryption. Call SetKeys first.");

            if (plaintext is null)
                throw new ArgumentNullException(nameof(plaintext));

            _des1.SetDirect(true);
            _des2.SetDirect(true);

            intermediate = _des1.Cipher(plaintext);
            var ciphertext = _des2.Cipher(intermediate);

            return ciphertext;
        }
    }
}