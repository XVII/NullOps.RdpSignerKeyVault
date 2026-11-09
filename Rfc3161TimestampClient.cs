using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace NullOps.RdpSigner;

internal static class Rfc3161TimestampClient
{
    private const string TimestampAttributeOid = "1.2.840.113549.1.9.16.2.14";
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";
    private static readonly HttpClient HttpClient = new();

    public static void AddTimestamp(SignedCms cmsPayload, Uri timestampServerUri)
    {
        if (timestampServerUri.Scheme != Uri.UriSchemeHttp && timestampServerUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("The timestamp URL must use HTTP or HTTPS.", nameof(timestampServerUri));
        }

        SignerInfo signerInfo = cmsPayload.SignerInfos[0];
        ReadOnlyMemory<byte> nonce = RandomNumberGenerator.GetBytes(16);
        Rfc3161TimestampRequest timestampRequest = Rfc3161TimestampRequest.CreateFromSignerInfo(
            signerInfo,
            HashAlgorithmName.SHA256,
            nonce: nonce,
            requestSignerCertificates: true);

        using HttpRequestMessage request = new(HttpMethod.Post, timestampServerUri)
        {
            Content = new ByteArrayContent(timestampRequest.Encode())
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/timestamp-reply"));

        using HttpResponseMessage response = HttpClient.Send(request);
        response.EnsureSuccessStatusCode();
        byte[] responseBytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        Rfc3161TimestampToken timestampToken = timestampRequest.ProcessResponse(responseBytes, out int bytesConsumed);
        if (bytesConsumed != responseBytes.Length)
        {
            throw new CryptographicException("The timestamp server returned trailing data after its response.");
        }

        if (!timestampToken.VerifySignatureForSignerInfo(signerInfo, out X509Certificate2 timestampCertificate)
            || timestampCertificate == null)
        {
            timestampCertificate?.Dispose();
            throw new CryptographicException("The timestamp token signature or signer imprint is invalid.");
        }

        using (timestampCertificate)
        using (X509Chain chain = new())
        {
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(TimestampingEkuOid));
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationTime = timestampToken.TokenInfo.Timestamp.UtcDateTime;

            if (!chain.Build(timestampCertificate))
            {
                string chainErrors = string.Join(", ", chain.ChainStatus.Select(status => status.StatusInformation.Trim()));
                throw new CryptographicException("The timestamp authority certificate chain is not trusted: " + chainErrors);
            }
        }

        cmsPayload.SignerInfos[0].AddUnsignedAttribute(
            new AsnEncodedData(new Oid(TimestampAttributeOid), timestampToken.AsSignedCms().Encode()));
    }
}
