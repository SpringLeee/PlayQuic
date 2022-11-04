using System;
using System.IO.Pipelines;
using System.IO.Pipes;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;

Console.WriteLine("Quic Server");

const long DefaultStreamErrorCodeClient = 123456;
const long DefaultStreamErrorCodeServer = 654321;
const long DefaultCloseErrorCodeClient = 789;
const long DefaultCloseErrorCodeServer = 987;

await using var listener = await QuicListener.ListenAsync(new QuicListenerOptions
{
    ApplicationProtocols = new List<System.Net.Security.SslApplicationProtocol> { SslApplicationProtocol.Http3 },
    ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 9999),
    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateQuicServerOptions())

});

await using var connection = await listener.AcceptConnectionAsync();

await using QuicStream stream = await connection.AcceptInboundStreamAsync();  



Console.ReadKey();

QuicServerConnectionOptions CreateQuicServerOptions()
{
    return new QuicServerConnectionOptions()
    {
        DefaultStreamErrorCode = DefaultStreamErrorCodeServer,
        DefaultCloseErrorCode = DefaultCloseErrorCodeServer,
        ServerAuthenticationOptions = GetSslServerAuthenticationOptions()
    };
}

SslServerAuthenticationOptions GetSslServerAuthenticationOptions()
{
    return new SslServerAuthenticationOptions()
    {
        ApplicationProtocols = new List<SslApplicationProtocol>() { SslApplicationProtocol.Http3 },
        ServerCertificate = GenerateManualCertificate()
    };
}


Console.ReadKey();


X509Certificate2 GenerateManualCertificate()
{
    X509Certificate2 cert = null;
    var store = new X509Store("KestrelWebTransportCertificates", StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadWrite);
    if (store.Certificates.Count > 0)
    {
        cert = store.Certificates[^1];

        // rotate key after it expires
        if (DateTime.Parse(cert.GetExpirationDateString(), null) < DateTimeOffset.UtcNow)
        {
            cert = null;
        }
    }
    if (cert == null)
    {
        // generate a new cert
        var now = DateTimeOffset.UtcNow;
        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddDnsName("localhost");
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req = new("CN=localhost", ec, HashAlgorithmName.SHA256);
        // Adds purpose
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new("1.3.6.1.5.5.7.3.1") // serverAuth
        }, false));
        // Adds usage
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        // Adds subject alternate names
        req.CertificateExtensions.Add(sanBuilder.Build());
        // Sign
        using var crt = req.CreateSelfSigned(now, now.AddDays(14)); // 14 days is the max duration of a certificate for this
        cert = new(crt.Export(X509ContentType.Pfx));

        // Save
        store.Add(cert);
    }
    store.Close();

    var hash = SHA256.HashData(cert.RawData);
    var certStr = Convert.ToBase64String(hash);
    Console.WriteLine($"\n\n\n\n\nCertificate: {certStr}\n\n\n\n"); // <-- you will need to put this output into the JS API call to allow the connection
    return cert;
}