using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Components.Forms;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace DigitalSignWebService.Data {
    public static class CryptoUtils {
        public enum KeySize {
            Bits512  = 512,
            Bits1024 = 1024,
        }

        public enum AsymmetricKeyGenAlgorithm {
            RSA = 1,
        }

        public enum SignatureAlgorithm
        {
            SHA512 = 1,
        }

        public interface ISignableFile {
            public byte[] GetFileData();
            public string GetSignatureAlgorithm();
            public byte[] GetSignature();
            public void   SetSignature(byte[] signature);
            public bool   IsSigned { get; }
        }

        public interface IVerifiableFile {
            public byte[]           GetFileData();
            public string           GetSignatureAlgorithm();
            public void             SetSignature(byte[] signature);
            public bool             IsSigned { get; }
            public X509Certificate2 GetCertificate();
            public void             SetCertificate(X509Certificate2 cert);
            public void             SetVerified(bool                verified);
            public bool             WasVerified { get; }
        }

        public class BrowserSignableFile : ISignableFile {
            public IBrowserFile       File;
            public SignatureAlgorithm SignatureAlgorithm;

            private byte[] _signature = null;
            public  bool   IsSigned => _signature != null;

            private BrowserSignableFile() {
            }

            public BrowserSignableFile(IBrowserFile file, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA512) {
                File               = file;
                SignatureAlgorithm = algorithm;
            }

            public byte[] GetFileData() {
                if (File == null) {
                    return null;
                }

                var fileData = new byte[File.Size];
                File.OpenReadStream().ReadAsync(fileData, 0, (int) File.Size);
                return fileData;
            }

            public string GetSignatureAlgorithm() {
                switch (SignatureAlgorithm) {
                    case SignatureAlgorithm.SHA512:
                        return PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(SignatureAlgorithm), SignatureAlgorithm, null);
                }
            }

            public byte[] GetSignature() {
                return _signature;
            }

            public void SetSignature(byte[] signature) {
                _signature = signature;
            }
        }

        public class BrowserVerifiableFile : IVerifiableFile {
            public  IBrowserFile       File;
            public  IBrowserFile       SignatureFile;
            public  SignatureAlgorithm SignatureAlgorithm;
            private byte[]             _signature;
            private X509Certificate2   _certificate;
            private bool               _verified = false;

            public bool VerificationResult;

            public bool IsSigned   => _signature != null;
            public bool WasVerified => _verified;

            private BrowserVerifiableFile() {
            }

            public BrowserVerifiableFile(IBrowserFile file, X509Certificate2 certificate = null, byte[] signature = null, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA512) {
                File               = file;
                SignatureAlgorithm = algorithm;
                _certificate       = certificate;
                _signature         = signature;
            }

            public byte[] GetFileData() {
                if (File == null) {
                    return null;
                }

                var fileData = new byte[File.Size];
                File.OpenReadStream().ReadAsync(fileData, 0, (int) File.Size);
                return fileData;
            }

            public string GetSignatureAlgorithm() {
                switch (SignatureAlgorithm) {
                    case SignatureAlgorithm.SHA512:
                        return PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(SignatureAlgorithm), SignatureAlgorithm, null);
                }
            }

            public byte[] GetSignature() {
                return _signature;
            }

            public void SetSignature(byte[] signature) {
                _signature = signature;
            }

            public X509Certificate2 GetCertificate() {
                return _certificate;
            }

            public void SetCertificate(X509Certificate2 cert) {
                _certificate = cert;
            }

            public void SetVerified(bool verified) {
                _verified = verified;
            }
        }
        
        public class Signature
        {
            public SignatureAlgorithm alg { get; set; }
            public string sign { get; set; }
        }

        private static string GetSignatureAlgorithmId(SignatureAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case SignatureAlgorithm.SHA512: return PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id;
                default: throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null);
            }
        }

        private static byte[] ReadFile(IBrowserFile file)
        {
            var fileData = new byte[file.Size];
            file.OpenReadStream().ReadAsync(fileData, 0, (int)file.Size);

            return fileData;
        }

        public static X509Certificate2 ImportCert(IBrowserFile file)
        {
            var fileData = ReadFile(file);
            X509Certificate2 certificate = new X509Certificate2();
            certificate.Import(fileData);

            return certificate;
        }

        public static string SignFile(IBrowserFile file, IBrowserFile priv_pem_key_file, SignatureAlgorithm algorithm)
        {
            var priv_pem_key = ReadFile(priv_pem_key_file);

            PemObject pemObject = new PemObject("PRIVATE KEY", priv_pem_key);

            AsymmetricKeyParameter privateKey = PublicKeyFactory.CreateKey(pemObject.Content);

            var fileData = ReadFile(file);

            var signer = SignerUtilities.GetSigner(GetSignatureAlgorithmId(algorithm));

            signer.Init(true, privateKey);

            signer.BlockUpdate(fileData, 0, fileData.Length);

            var signedString = Convert.ToBase64String(signer.GenerateSignature());

            Signature sig = new Signature() { alg = algorithm, sign = signedString };

            return JsonSerializer.Serialize(sig);
        }

        public static bool Verify(IBrowserFile file, string expected, X509Certificate2 certificate)
        {
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(certificate.GetPublicKey());

            Signature sig = JsonSerializer.Deserialize<Signature>(expected);

            var fileData = ReadFile(file);

            var signer = SignerUtilities.GetSigner(GetSignatureAlgorithmId(sig.alg));

            signer.Init(false, publicKey);

            signer.BlockUpdate(fileData, 0, fileData.Length);

            var expectedSig = Convert.FromBase64String(sig.sign);

            return signer.VerifySignature(expectedSig);
        }

        public static X509Certificate2 GenerateSelfSignedCertificate(AsymmetricKeyGenAlgorithm algorithm, int keyStrength, string subjectName, out PrivateKeyInfo privateKeyInfo) {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random          = new SecureRandom(randomGenerator);

            // Keypair Generator
            var kpGenerator = GetAsymmetricKeyPairGenerator(algorithm, keyStrength, random);

            // Create a keypair
            var subjectKeyPair = kpGenerator.GenerateKeyPair();

            return GenerateCertificate(subjectKeyPair, subjectName, subjectName, subjectKeyPair.Private, random, out privateKeyInfo);
        }

        public static X509Certificate2 GenerateCertificate(AsymmetricKeyGenAlgorithm algorithm, int keyStrength, string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivateKey, SecureRandom random, out PrivateKeyInfo privateKeyInfo) {
            // Random number generator
            random ??= new SecureRandom(new CryptoApiRandomGenerator());

            // Keypair Generator
            var kpGenerator = GetAsymmetricKeyPairGenerator(algorithm, keyStrength, random);

            // Create a keypair
            var subjectKeyPair = kpGenerator.GenerateKeyPair();

            return GenerateCertificate(subjectKeyPair, subjectName, issuerName, issuerPrivateKey, random, out privateKeyInfo);
        }

        public static X509Certificate2 GenerateCertificate(AsymmetricCipherKeyPair subjectKeyPair, string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivateKey, SecureRandom random, out PrivateKeyInfo privateKeyInfo) {
            // Random number generator
            random ??= new SecureRandom(new CryptoApiRandomGenerator());

            // Signature Factory
            var issuerSignFactory = GetSignatureFactory(issuerPrivateKey, random);

            // Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            certificateGenerator.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random));

            // Issuer and Subject Names
            certificateGenerator.SetSubjectDN(new X509Name(subjectName));
            certificateGenerator.SetIssuerDN(new X509Name(issuerName));

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter  = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Sign certificate
            var certificate = certificateGenerator.Generate(issuerSignFactory);

            // Corresponding private key
            privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);

            // Merge into X509Certificate2
            return new X509Certificate2(certificate.GetEncoded());
        }

        private static IAsymmetricCipherKeyPairGenerator GetAsymmetricKeyPairGenerator(AsymmetricKeyGenAlgorithm algorithm, int keyStrength, SecureRandom random) {
            IAsymmetricCipherKeyPairGenerator kpGenerator;

            // TODO: support different algorithms

            switch (algorithm) {
                case AsymmetricKeyGenAlgorithm.RSA:
                    kpGenerator = new RsaKeyPairGenerator();
                    break;

                default: return null;
            }

            random ??= new SecureRandom(new CryptoApiRandomGenerator());
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);

            kpGenerator.Init(keyGenerationParameters);
            return kpGenerator;
        }

        private static ISignatureFactory GetSignatureFactory(AsymmetricKeyParameter privateKey, SecureRandom random) {
            // TODO: support different algorithms?
            return new Asn1SignatureFactory("SHA224withRSA", privateKey, random);
        }

        public static void ExportPublicKey(RSA rsa, TextWriter outputStream) {
            var parameters = rsa.ExportParameters(false);
            using (var stream = new MemoryStream()) {
                var writer = new BinaryWriter(stream);
                writer.Write((byte) 0x30); // SEQUENCE
                using (var innerStream = new MemoryStream()) {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte) 0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte) 0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte) 0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte) 0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream()) {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte) 0x00); // # of unused bits
                        bitStringWriter.Write((byte) 0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream()) {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus);  // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int) paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }

                        var bitStringLength = (int) bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }

                    var length = (int) innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int) stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                for (var i = 0; i < base64.Length; i += 64) {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }

                outputStream.WriteLine("-----END PUBLIC KEY-----");
            }
        }

        public static void ExportPrivateKey(RSA rsa, TextWriter outputStream) {
            var parameters = rsa.ExportParameters(true);
            using (var stream = new MemoryStream()) {
                var writer = new BinaryWriter(stream);
                writer.Write((byte) 0x30); // SEQUENCE
                using (var innerStream = new MemoryStream()) {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] {0x00}); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int) innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int) stream.Length).ToCharArray();
                outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64) {
                    outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                }

                outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length) {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80) {
                // Short form
                stream.Write((byte) length);
            } else {
                // Long form
                var temp          = length;
                var bytesRequired = 0;
                while (temp > 0) {
                    temp >>= 8;
                    bytesRequired++;
                }

                stream.Write((byte) (bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--) {
                    stream.Write((byte) (length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true) {
            stream.Write((byte) 0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++) {
                if (value[i] != 0) break;
                prefixZeros++;
            }

            if (value.Length - prefixZeros == 0) {
                EncodeLength(stream, 1);
                stream.Write((byte) 0);
            } else {
                if (forceUnsigned && value[prefixZeros] > 0x7f) {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte) 0);
                } else {
                    EncodeLength(stream, value.Length - prefixZeros);
                }

                for (var i = prefixZeros; i < value.Length; i++) {
                    stream.Write(value[i]);
                }
            }
        }
    }
}