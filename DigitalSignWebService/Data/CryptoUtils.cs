using System;
using System.Security.Cryptography;

namespace DigitalSignWebService.Data {
    public static class CryptoUtils {
        public enum KeySize {
            Bits515  = 515,
            Bits1024 = 1024,
        }

        public enum KeyGenAlgorithm {
            RSA = 1,
        }


        public static bool TryGenerateKeyPair(KeyGenAlgorithm algorithm, KeySize keySize, out string publicKey, out string privateKey) {
            switch (algorithm) {
                case KeyGenAlgorithm.RSA: return TryGenerateKeyPairRsa(keySize, out publicKey, out privateKey);
            }

            publicKey  = null;
            privateKey = null;
            return false;
        }

        private static bool TryGenerateKeyPairRsa(KeySize keySize, out string publicKey, out string privateKey) {
            try {
                var result = RSA.Create((int) keySize);
                publicKey  = System.Text.Encoding.Default.GetString(result.ExportRSAPublicKey());
                privateKey = System.Text.Encoding.Default.GetString(result.ExportRSAPrivateKey());
                return true;
            } catch (Exception e) {
                publicKey  = e.Message;
                privateKey = e.Message;
                return false;
            }
        }
    }
}