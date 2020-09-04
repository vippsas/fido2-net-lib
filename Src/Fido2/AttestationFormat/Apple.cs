using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Asn1;
using Fido2NetLib.Objects;
using PeterO.Cbor;

namespace Fido2NetLib.AttestationFormat
{

    internal class Apple : AttestationFormat
    {
        private readonly IMetadataService _metadataService;
        public Apple(CBORObject attStmt, byte[] authenticatorData, byte[] clientDataHash, IMetadataService metadataService)
            : base(attStmt, authenticatorData, clientDataHash)
        {
            _metadataService = metadataService;
        }

        public override void Verify()
        {
            // Reference: https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server

            // Verify that attStmt is valid CBOR conforming to the syntax defined above and
            // perform CBOR decoding on it to extract the contained fields.
            if (0 == attStmt.Keys.Count || 0 == attStmt.Values.Count)
                throw new Fido2VerificationException("Attestation format apple must have attestation statement");

            if (null == Alg || true != Alg.IsNumber)
                throw new Fido2VerificationException("Invalid apple attestation algorithm");

            // Verify that x5c is present
            if (null == X5c || CBORType.Array != X5c.Type || 0 == X5c.Count || null != EcdaaKeyId)
                throw new Fido2VerificationException("Malformed x5c array in apple attestation statement");

            // Validate certificate lifetimes
            using var enumerator = X5c.Values.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (null == enumerator.Current
                    || CBORType.ByteString != enumerator.Current.Type
                    || 0 == enumerator.Current.GetByteString().Length)
                    throw new Fido2VerificationException("Malformed x5c cert found in apple attestation statement");

                var x5ccert = new X509Certificate2(enumerator.Current.GetByteString());

                // X509Certificate2.NotBefore/.NotAfter return LOCAL DateTimes, so
                // it's correct to compare using DateTime.Now.
                if (DateTime.Now < x5ccert.NotBefore || DateTime.Now > x5ccert.NotAfter)
                    throw new Fido2VerificationException("One or more of the signing certificates in x5c expired or not yet valid");
            }

            // The attestation certificate attestnCert MUST be the first element in the array.
            var attestnCert = new X509Certificate2(X5c.Values.First().GetByteString());

            // Version MUST be set to 3
            if (3 != attestnCert.Version)
                throw new Fido2VerificationException("Apple x5c attestation certificate not V3");

            // The Basic Constraints extension MUST have the CA component set to false
            if (IsAttnCertCACert(attestnCert.Extensions))
                throw new Fido2VerificationException("Attestation certificate has CA cert flag present");

            // Verify that the x5c array contains the intermediate and leaf certificates for attestation,
            // starting from the credential certificate stored in the first data buffer in the array.
            // Verify the validity of the certificates using Apple's Webauthn Root CA
            var trustPath = X5c.Values
                .Select(x => new X509Certificate2(x.GetByteString()))
                .ToArray();

            // If the authenticator is listed in the metadata as one that should produce a basic full attestation, build and verify the chain
            var entry = _metadataService?.GetEntry(AuthData.AttestedCredentialData.AaGuid);

            // while conformance testing, we must reject any authenticator that we cannot get metadata for
            if (_metadataService?.ConformanceTesting() == true && null == entry)
                throw new Fido2VerificationException("AAGUID not found in MDS test metadata");

            // If the authenticator is listed in the metadata as one that should produce a basic full attestation, build and verify the chain
            if (entry?.MetadataStatement?.AttestationTypes.Contains((ushort)MetadataAttestationType.ATTESTATION_BASIC_FULL) ?? false)
            {
                var attestationRootCertificates = entry.MetadataStatement.AttestationRootCertificates
                    .Select(x => new X509Certificate2(Convert.FromBase64String(x)))
                    .ToArray();

                if (false == ValidateTrustChain(trustPath, attestationRootCertificates))
                {
                    throw new Fido2VerificationException("Invalid certificate chain in apple attestation");
                }
            }

            // 2. Create clientDataHash as the SHA256 hash of the client data, and append that hash to the end of the authenticator
            // data (authData from the decoded object). The "Data" property contains this concatenation.
            // 3. Generate SHA-256 hash of the concatenation of authData and clientDataHash, i.e. SHA256(authData || SHA256(clientData))
            var expectedNonce = SHA256.Create().ComputeHash(Data);

            // 4. Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2, whihc is a DER-encoded ASN.1 sequence.
            // Decode the sequence and extract the single octet string that it contains. Verify that the string equals nonce.
            var nonceInCert = NonceFromAttnCertExts(attestnCert.Extensions);
            if (nonceInCert == null)
            {
                throw new Fido2VerificationException("Missing nonce in certificate");
            }
            if (!nonceInCert.SequenceEqual(expectedNonce))
            {
                throw new Fido2VerificationException("Invalid nonce in certificate");
            }

            // Verify that the public key in certificate is equal to the public key in the authenticator data
            var publicKeyFromAuthdata = AuthData.AttestedCredentialData.CredentialPublicKey;
            var publicKeyFromCert = new CredentialPublicKey(attestnCert, Alg.AsInt32());

            if(!publicKeyFromAuthdata.GetCBORObject().Equals(publicKeyFromCert.GetCBORObject()))
            {
                throw new Fido2VerificationException(
                    "Public keys in attestation certificate and authenticator data do not match");
            }

        }

        internal static byte[] NonceFromAttnCertExts(X509ExtensionCollection exts)
        {
            byte[] nonce = null;
            foreach (var ext in exts)
            {
                if (ext.Oid.Value.Equals("1.2.840.113635.100.8.2")) // apple nonce
                {
                    var decodedNonceSeq = AsnElt.Decode(ext.RawData);
                    decodedNonceSeq.CheckTag(AsnElt.SEQUENCE);
                    decodedNonceSeq.CheckNumSub(1);
                    var decodedNonce = decodedNonceSeq.Sub[0];
                    decodedNonce.CheckTag(AsnElt.CONTEXT, 1);
                    decodedNonce.CheckNumSub(1);
                    decodedNonce = decodedNonce.Sub[0];
                    decodedNonce.CheckTag(AsnElt.OCTET_STRING);
                    decodedNonce.CheckPrimitive();
                    nonce = decodedNonce.GetOctetString();

                    //The extension MUST NOT be marked as critical
                    if (true == ext.Critical)
                        throw new Fido2VerificationException("extension MUST NOT be marked as critical");
                }
            }
            return nonce;
        }

    }
}
