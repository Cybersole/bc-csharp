using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Async;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Ech
{
    public static class ECH
    {
        public const byte ECHClientHelloInnerVariant = 1;
        public const byte ECHClientHelloOuterVariant = 0;

        public const ushort ExtensionECH = 0xfe0d;
        public const ushort ExtensionECHOuterExtensions = 0xfd00;

        public static (ClientHello, ClientHello) OfferECH(ClientHello helloBase, ECHConfig config)
        {
            var serverName = helloBase.Extensions[ExtensionType.server_name];
            var supportedVersions = helloBase.Extensions[ExtensionType.supported_versions];

            if(config is null) //GREASE
            {
                var dummyEncodedHelloInnerLen = 100;

                config = ECHConfig.GetGrease();

                var echGrease = new ECHClientOuter();
                echGrease.Handle.Enc = config.SetupSealer().GetEncapsulation();
                echGrease.Handle.Suite = config.Suites[0];
                echGrease.Handle.ConfigId = config.ConfigId;
                echGrease.Payload = new byte[dummyEncodedHelloInnerLen + 16];

                Random.Shared.NextBytes(echGrease.Payload);

                helloBase.Extensions[ExtensionECH] = echGrease.ToBytes();

                return (null, helloBase);
            }

            var ctx = config.SetupSealer();

            var ech = new ECHClientOuter();
            ech.Handle.Enc = ctx.GetEncapsulation();
            ech.Handle.Suite = config.Suites[0];
            ech.Handle.ConfigId = config.ConfigId;

            var helloInnerOutput = new MemoryStream();
            var helloOuterOutput = new MemoryStream();

            helloBase.Extensions[ExtensionECH] = [ECHClientHelloInnerVariant];
            helloBase.Extensions[ExtensionType.supported_versions] = TlsExtensionsUtilities
                .CreateSupportedVersionsExtensionClient([ProtocolVersion.TLSv13]);

            helloBase.Encode(helloInnerOutput);

            var helloInner = helloInnerOutput.ToArray();

            var echInner = EncodeHelloInner(helloInner, serverName.Length, config.MaxNameLen);
            var cipherLen = echInner.Length + 16;

            var newHello = new ClientHello(helloBase.Version, helloBase.Random, helloBase.SessionID,
                helloBase.Cookie, helloBase.CipherSuites, new Dictionary<int, byte[]>(helloBase.Extensions), helloBase.BindersSize);

            newHello.Extensions[ExtensionType.server_name] = TlsExtensionsUtilities
                .CreateServerNameExtensionClient([new ServerName(0, config.RawPublicName)]);
            newHello.Extensions[ExtensionECH] = ech.ToBytes();
            newHello.Extensions[ExtensionType.supported_versions] = supportedVersions;

            newHello.Encode(helloOuterOutput);

            var helloOuter = helloOuterOutput.ToArray();

            var echOutter = EncodeHelloOuterAAD(helloOuter, (uint)cipherLen);

            ech.Payload = ctx.Seal(echOutter, echInner);

            newHello.Extensions[ExtensionECH] = ech.ToBytes();

            return (helloBase, newHello);
        }
        public static byte[] EncodeHelloOuterAAD(byte[] hello, uint payloadLen)
        {
            using var ms = new MemoryStream(hello);

            var version = TlsUtilities.ReadUint16(ms);
            var random = new byte[32];

            ms.Read(random);

            var sessionId = TlsUtilities.ReadOpaque8(ms);
            var cipherSuites = TlsUtilities.ReadOpaque16(ms);
            var compression = TlsUtilities.ReadOpaque8(ms);
            var extensions = TlsUtilities.ReadOpaque16(ms);

            var output = new MemoryStream();

            TlsUtilities.WriteUint16(version, output);

            output.Write(random);

            TlsUtilities.WriteOpaque8(sessionId, output);
            TlsUtilities.WriteOpaque16(cipherSuites, output);

            TlsUtilities.WriteOpaque8(compression, output);

            var extStream = new MemoryStream(extensions);
            var extOutput = new MemoryStream();

            while (extStream.Position < extStream.Length)
            {
                var ext = TlsUtilities.ReadUint16(extStream);
                var data = TlsUtilities.ReadOpaque16(extStream);

                if (ext == ExtensionECH) 
                {
                    var ech = ECHClientOuter.FromBytes(data);
                    ech.Payload = new byte[payloadLen];
                    ech.Raw = null;

                    data = ech.ToBytes();
                }

                TlsUtilities.WriteUint16(ext, extOutput);
                TlsUtilities.WriteOpaque16(data, extOutput);
            }

            TlsUtilities.WriteOpaque16(extOutput.ToArray(), output);

            return output.ToArray();
        }

        public static byte[] EncodeHelloInner(byte[] hello, int serverNameLen, int maxNameLen)
        {
            using var ms = new MemoryStream(hello);

            //var msgType = TlsUtilities.ReadUint8(ms);
            //var length = TlsUtilities.ReadUint24(ms);

            var version = TlsUtilities.ReadUint16(ms);
            var random = new byte[32];

            ms.Read(random);

            var sessionId = TlsUtilities.ReadOpaque8(ms);
            var cipherSuites = TlsUtilities.ReadOpaque16(ms);
            var compression = TlsUtilities.ReadOpaque8(ms);
            var extensions = TlsUtilities.ReadOpaque16(ms);

            var output = new MemoryStream();

            TlsUtilities.WriteUint16(version, output);

            output.Write(random);

            TlsUtilities.WriteUint8(0, output);
            TlsUtilities.WriteOpaque16(cipherSuites, output);

            TlsUtilities.WriteOpaque8(compression, output);

            var extStream = new MemoryStream(extensions);
            var extOutput = new MemoryStream();

            while (extStream.Position < extStream.Length)
            {
                var ext = TlsUtilities.ReadUint16(extStream);
                var data = TlsUtilities.ReadOpaque16(extStream);

                if (ext == ExtensionType.key_share)
                {
                    TlsUtilities.WriteUint16(ExtensionECHOuterExtensions, extOutput);

                    TlsUtilities.WriteUint16(3, extOutput);

                    TlsUtilities.WriteUint8(2, extOutput);
                    TlsUtilities.WriteUint16(51, extOutput);
                }
                else
                {
                    TlsUtilities.WriteUint16(ext, extOutput);
                    TlsUtilities.WriteOpaque16(data, extOutput);
                }
            }

            TlsUtilities.WriteOpaque16(extOutput.ToArray(), output);

            var paddingLen = 0;

            if (serverNameLen > 0)
            {
                var n = maxNameLen - serverNameLen;

                if (n > 0) paddingLen += n;
            }
            else
            {
                paddingLen += 9 + maxNameLen;
            }

            paddingLen = 31 - (((int)output.Length + paddingLen - 1) % 32);

            output.Write(new byte[paddingLen]);

            return output.ToArray();
        }
    }
}
