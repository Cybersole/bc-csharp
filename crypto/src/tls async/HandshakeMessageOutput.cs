using System;
using System.IO;
using System.Threading.Tasks;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Async
{
    internal sealed class HandshakeMessageOutput
        : MemoryStream
    {
        internal static int GetLength(int bodyLength)
        {
            return 4 + bodyLength;
        }

        /// <exception cref="IOException"/>
        internal static async Task Send(TlsProtocol protocol, short handshakeType, byte[] body)
        {
            HandshakeMessageOutput message = new HandshakeMessageOutput(handshakeType, body.Length);
            message.Write(body, 0, body.Length);
            await message.SendAsync(protocol);
        }

        /// <exception cref="IOException"/>
        internal HandshakeMessageOutput(short handshakeType)
            : this(handshakeType, 60)
        {
        }

        /// <exception cref="IOException"/>
        internal HandshakeMessageOutput(short handshakeType, int bodyLength)
            : base(GetLength(bodyLength))
        {
            TlsUtilities.CheckUint8(handshakeType);
            TlsUtilities.WriteUint8(handshakeType, this);
            // Reserve space for length
            Seek(3L, SeekOrigin.Current);
        }

        /// <exception cref="IOException"/>
        internal async Task SendAsync(TlsProtocol protocol)
        {
            // Patch actual length back in
            int bodyLength = Convert.ToInt32(Length) - 4;
            TlsUtilities.CheckUint24(bodyLength);

            Seek(1L, SeekOrigin.Begin);
            TlsUtilities.WriteUint24(bodyLength, this);

            byte[] buf = GetBuffer();
            int count = Convert.ToInt32(Length);

            await protocol.WriteHandshakeMessageAsync(buf, 0, count);

            Dispose();
        }

        internal void PrepareClientHello(TlsHandshakeHash handshakeHash, int bindersSize)
        {
            // Patch actual length back in
            int bodyLength = Convert.ToInt32(Length) - 4 + bindersSize;
            TlsUtilities.CheckUint24(bodyLength);

            Seek(1L, SeekOrigin.Begin);
            TlsUtilities.WriteUint24(bodyLength, this);

            byte[] buf = GetBuffer();
            int count = Convert.ToInt32(Length);

            handshakeHash.Update(buf, 0, count);

            Seek(0L, SeekOrigin.End);
        }

        internal async Task SendClientHelloAsync(TlsClientProtocol clientProtocol, TlsHandshakeHash handshakeHash, int bindersSize)
        {
            byte[] buf = GetBuffer();
            int count = Convert.ToInt32(Length);

            if (bindersSize > 0)
            {
                handshakeHash.Update(buf, count - bindersSize, bindersSize);
            }

            await clientProtocol.WriteHandshakeMessageAsync(buf, 0, count);

            Dispose();
        }
    }
}
