using System.Buffers;
using System.IO;
using System.IO.Pipelines;
using System.IO.Pipes;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Xml.Linq;

Console.WriteLine("Quic Client Running...");

await Task.Delay(3000);

// 连接到服务端
var connection = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
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

for (int j = 0; j < 5; j++)
{
    _ = Task.Run(async () => {

        // 打开一个出站的双向流
        var stream = await connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional); 
      
        var writer = PipeWriter.Create(stream); 

        Console.WriteLine();

        // 写入数据
        await Task.Delay(2000);

        var message = $"Hello Quic [{stream.Id}] \n";

        Console.Write("Send -> " + message);

        await writer.WriteAsync(Encoding.UTF8.GetBytes(message));

        await writer.CompleteAsync(); 
    });  
} 


Console.ReadKey();  