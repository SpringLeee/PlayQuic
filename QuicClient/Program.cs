using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Xml.Linq;

Console.WriteLine("QuicClient");

await Task.Delay(5000);

await using var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
{
    DefaultCloseErrorCode = 0,
    DefaultStreamErrorCode = 0,
    RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, 9999),
    ClientAuthenticationOptions = new SslClientAuthenticationOptions
    {
        ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http3 },
        RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
        {
            return true;
        }
    }
});

await using QuicStream stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional);
 
for (int i = 0; i < 100; i++)
{
    await Task.Delay(1000);
    Console.WriteLine(i.ToString());
    await stream.WriteAsync(System.Text.UTF8Encoding.UTF8.GetBytes("hello quic: " + DateTime.Now.ToLongDateString()), completeWrites: true);
}
 
Console.ReadKey();


async Task<int> WriteForever(QuicStream stream, int size = 1)
{
    byte[] buffer = ArrayPool<byte>.Shared.Rent(size);
    try
    {
        while (true)
        {
            await stream.WriteAsync(buffer);
        }
    }
    finally
    {
        ArrayPool<byte>.Shared.Return(buffer);
    }
}