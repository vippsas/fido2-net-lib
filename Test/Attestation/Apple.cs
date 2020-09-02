using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Asn1;
using fido2_net_lib.Test;
using Fido2NetLib;
using Fido2NetLib.Objects;
using PeterO.Cbor;
using Xunit;

namespace Test.Attestation
{
    public class Apple : Fido2Tests.Attestation
    {
        public Oid oidAppleNonce = new Oid("1.2.840.113635.100.8.2");

        public Apple()
        {
            _attestationObject = CBORObject.NewMap().Add("fmt", "apple");
            _aaguid = new Guid("00000000-0000-0000-0000-000000000000");

        }

        [Fact]
        public async Task TestSelf()
        {
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", COSE.Algorithm.ES256)
                .Add("x5c", MakeX5C()));

            var res = await MakeAttestationResponse();

            Assert.Equal(string.Empty, res.ErrorMessage);
            Assert.Equal("ok", res.Status);
            Assert.Equal(_aaguid, res.Result.Aaguid);
            Assert.Equal(_signCount, res.Result.Counter);
            Assert.Equal("apple", res.Result.CredType);
            Assert.Equal(_credentialID, res.Result.CredentialId);
            Assert.Null(res.Result.ErrorMessage);
            Assert.Equal(_credentialPublicKey.GetBytes(), res.Result.PublicKey);
            Assert.Null(res.Result.Status);
            Assert.Equal("Test User", res.Result.User.DisplayName);
            Assert.Equal(System.Text.Encoding.UTF8.GetBytes("testuser"), res.Result.User.Id);
            Assert.Equal("testuser", res.Result.User.Name);
        }

        [Fact]
        public void TestMissingAlg()
        {
            _attestationObject.Add("attStmt", CBORObject.NewMap().Add("x5c", MakeX5C()));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Invalid apple attestation algorithm", ex.Result.Message);
        }

        [Fact]
        public void TestAlgNaN()
        {
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", "invalid alg")
                .Add("x5c", MakeX5C()));
            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Invalid apple attestation algorithm", ex.Result.Message);
        }


        private X509Extension MakeAppleNonceExt(ECDsa ecdsa)
        {
            var ecparams = ecdsa.ExportParameters(true);
            _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

            var asnEncodedHash = AsnElt.MakeBlob(_attToBeSignedHash(HashAlgorithmName.SHA256));
            var asnContext = AsnElt.Make(AsnElt.CONTEXT, 1, asnEncodedHash);
            var asnSequence = AsnElt.Make(AsnElt.SEQUENCE, asnContext).Encode();

            return new X509Extension(oidAppleNonce, asnSequence, false);
        }

        private CBORObject MakeX5C()
        {
            var attDN = new X500DistinguishedName("CN=Testing, OU=AAA Certification, O=Apple Inc., C=US");

            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))
                using (var ecdsaAtt = ECDsa.Create(ECCurve.NamedCurves.nistP256))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(MakeAppleNonceExt(ecdsaAtt));

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }

                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(root.RawData));
                    return X5c;

                }
            }
        }

        [Fact]
        public void TestMissingX5c()
        {
            MakeX5C(); // Evaluated for side effects

            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", COSE.Algorithm.ES256)
                .Add("x5c", null));

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Malformed x5c array in apple attestation statement", ex.Result.Message);
        }

        [Fact]
        public void TestX5cNotArray()
        {
            MakeX5C(); // Evaluated for side effects

            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", COSE.Algorithm.ES256)
                .Add("x5c", "boomerang"));

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Malformed x5c array in apple attestation statement", ex.Result.Message);
        }

        [Fact]
        public void TestX5cCountNotOne()
        {
            MakeX5C(); // Evaluated for side effects

            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", COSE.Algorithm.ES256)
                .Add("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0])).Add(CBORObject.FromObject(new byte[0]))));

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Malformed x5c cert found in apple attestation statement", ex.Result.Message);
        }

        [Fact]
        public void TestX5cValueNotByteString()
        {
            MakeX5C(); // Evaluated for side effects

            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", COSE.Algorithm.ES256)
                .Add("x5c", "x".ToArray()));

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Malformed x5c cert found in apple attestation statement", ex.Result.Message);
        }

        [Fact]
        public void TestX5cValueZeroLengthByteString()
        {
            MakeX5C(); // Evaluated for side effects

            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", COSE.Algorithm.ES256)
                .Add("x5c", CBORObject.NewArray().Add(CBORObject.FromObject(new byte[0]))));

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Malformed x5c cert found in apple attestation statement", ex.Result.Message);
        }

        [Fact]
        public void TestX5cCertExpired()
        {
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-7);
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=AAA Certification, O=Apple Inc., C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(MakeAppleNonceExt(ecdsaAtt));

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(root.RawData));

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
                    Assert.Equal("Apple signing certificate expired or not yet valid", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestX5cCertNotYetValid()
        {
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(1);
            DateTimeOffset notAfter = notBefore.AddDays(7);
            var attDN = new X500DistinguishedName("CN=Testing, OU=AAA Certification, O=Apple Inc., C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(MakeAppleNonceExt(ecdsaAtt));

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(root.RawData));

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
                    Assert.Equal("Apple signing certificate expired or not yet valid", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestInvalidAlg()
        {
            var X5c = MakeX5C();
            _attestationObject.Add("attStmt", CBORObject.NewMap()
                .Add("alg", 42)
                .Add("x5c", X5c));

            var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
            Assert.Equal("Public keys in attestation certificate and authenticator data do not match", ex.Result.Message);
        }

        [Fact]
        public void TestInvalidNonce()
        {
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=AAA Certification, O=Apple Inc., C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    var ecparams = ecdsaAtt.ExportParameters(true);
                    _credentialPublicKey = Fido2Tests.MakeCredentialPublicKey(COSE.KeyType.EC2, COSE.Algorithm.ES256, COSE.EllipticCurve.P256, ecparams.Q.X, ecparams.Q.Y);

                    var asnEncodedHash = AsnElt.MakeBlob(new byte[]
                    {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                    });
                    var asnContext = AsnElt.Make(AsnElt.CONTEXT, 1, asnEncodedHash);
                    var asnSequence = AsnElt.Make(AsnElt.SEQUENCE, asnContext).Encode();

                    attRequest.CertificateExtensions.Add(new X509Extension(oidAppleNonce, asnSequence, false));

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(root.RawData));

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
                    Assert.Equal("Invalid nonce in certificate", ex.Result.Message);
                }
            }
        }

        [Fact]
        public void TestAttCertNotV3()
        {
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=AAA Certification, O=Apple Inc., C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(notCAExt);

                    attRequest.CertificateExtensions.Add(MakeAppleNonceExt(ecdsaAtt));

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var rawAttestnCert = attestnCert.RawData;
                    rawAttestnCert[12] = 0x41;

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(rawAttestnCert))
                        .Add(CBORObject.FromObject(root.RawData));

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c));

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    {
                        // Actually throws Interop.AppleCrypto.AppleCommonCryptoCryptographicException
                        var ex = Assert.ThrowsAnyAsync<CryptographicException>(MakeAttestationResponse);
                        Assert.Equal("Unknown format in import.", ex.Result.Message);
                    }

                    else
                    {
                        var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
                        Assert.Equal("Apple x5c attestation certificate not V3", ex.Result.Message);
                    }
                }
            }
        }

        [Fact]
        public void TestAttCertCAFlagSet()
        {
            X509Certificate2 root, attestnCert;
            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore.AddDays(2);
            var attDN = new X500DistinguishedName("CN=Testing, OU=AAA Certification, O=Apple Inc., C=US");

            using (var ecdsaRoot = ECDsa.Create())
            {
                var rootRequest = new CertificateRequest(rootDN, ecdsaRoot, HashAlgorithmName.SHA256);
                rootRequest.CertificateExtensions.Add(caExt);

                ECCurve eCCurve = ECCurve.NamedCurves.nistP256;
                using (root = rootRequest.CreateSelfSigned(
                    notBefore,
                    notAfter))

                using (var ecdsaAtt = ECDsa.Create(eCCurve))
                {
                    var attRequest = new CertificateRequest(attDN, ecdsaAtt, HashAlgorithmName.SHA256);
                    attRequest.CertificateExtensions.Add(caExt);

                    attRequest.CertificateExtensions.Add(MakeAppleNonceExt(ecdsaAtt));

                    byte[] serial = new byte[12];

                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(serial);
                    }
                    using (X509Certificate2 publicOnly = attRequest.Create(
                        root,
                        notBefore,
                        notAfter,
                        serial))
                    {
                        attestnCert = publicOnly.CopyWithPrivateKey(ecdsaAtt);
                    }

                    var X5c = CBORObject.NewArray()
                        .Add(CBORObject.FromObject(attestnCert.RawData))
                        .Add(CBORObject.FromObject(root.RawData));

                    _attestationObject.Add("attStmt", CBORObject.NewMap()
                        .Add("alg", COSE.Algorithm.ES256)
                        .Add("x5c", X5c));

                    var ex = Assert.ThrowsAsync<Fido2VerificationException>(MakeAttestationResponse);
                    Assert.Equal("Attestation certificate has CA cert flag present", ex.Result.Message);
                }
            }

        }
    }
}
