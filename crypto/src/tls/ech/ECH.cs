using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Org.BouncyCastle.Tls.Ech
{
    public static class ECH
    {
        public const byte ECHClientHelloInnerVariant = 1;
        public const byte ECHClientHelloOuterVariant = 0;

        public const ushort ExtensionECH = 0xfe0d;
        public const ushort ExtensionECHOuterExtensions = 0xfd00;

        public static readonly int[] RequiredExtensions = [ExtensionType.ech, ExtensionType.server_name, ExtensionType.supported_versions];

        public static (ClientHello, ClientHello) OfferECH(ClientHello helloBase, ECHConfig config)
        {
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

            var newHello = new ClientHello(helloBase.Version, helloBase.Random, helloBase.SessionID,
                helloBase.Cookie, helloBase.CipherSuites, new Dictionary<int, byte[]>(helloBase.Extensions), helloBase.BindersSize);

            foreach (var extension in newHello.Extensions)
                if (!CompressExtension(extension.Key) && !RequiredExtensions.Contains(extension.Key))
                    newHello.Extensions.Remove(extension.Key);

            newHello.Extensions[ExtensionType.server_name] = TlsExtensionsUtilities
                .CreateServerNameExtensionClient([new ServerName(0, config.RawPublicName)]);
            newHello.Extensions[ExtensionECH] = ech.ToBytes();

            helloBase.Extensions[ExtensionECH] = [ECHClientHelloInnerVariant];
            helloBase.Extensions[ExtensionType.supported_versions] = TlsExtensionsUtilities
                .CreateSupportedVersionsExtensionClient([ProtocolVersion.TLSv13]);

            var serverName = helloBase.Extensions[ExtensionType.server_name];
            var echInner = EncodeHelloInner(helloBase, serverName.Length, config.MaxNameLen);
            var cipherLen = echInner.Length + 16;         

            var echOutter = EncodeHelloOuterAAD(newHello, (uint)cipherLen);

            ech.Payload = ctx.Seal(echOutter, echInner);

            newHello.Extensions[ExtensionECH] = ech.ToBytes();

            return (helloBase, newHello);
        }

        public static bool CompressExtension(int extension) => !RequiredExtensions.Contains(extension);

        public static byte[] EncodeHelloOuterAAD(ClientHello hello, uint payloadLen)
        {
            using var ms = new MemoryStream();
            hello.Encode(ms);
            ms.Position = 0;

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

        public static byte[] EncodeHelloInner(ClientHello hello, int serverNameLen, int maxNameLen)
        {
            using var ms = new MemoryStream();
            hello.Encode(ms);
            ms.Position = 0;

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
            var outerExtOutput = new MemoryStream();

            var oldExtensions = new Dictionary<int, byte[]>(hello.Extensions);

            hello.Extensions.Clear();

            foreach (var ext in oldExtensions)
                if (!CompressExtension(ext.Key))
                    hello.Extensions[ext.Key] = ext.Value;

            foreach (var ext in oldExtensions)
                if (!hello.Extensions.ContainsKey(ext.Key))
                    hello.Extensions[ext.Key] = ext.Value;

            while (extStream.Position < extStream.Length)
            {
                var ext = TlsUtilities.ReadUint16(extStream);
                var data = TlsUtilities.ReadOpaque16(extStream);
            
                if (!CompressExtension(ext))
                {
                    TlsUtilities.WriteUint16(ext, extOutput);
                    TlsUtilities.WriteOpaque16(data, extOutput);

                }
                else
                {
                    TlsUtilities.WriteUint16(ext, outerExtOutput);
                }        
            }

            if(outerExtOutput.Length > 0)
            {
                TlsUtilities.WriteUint16(ExtensionECHOuterExtensions, extOutput);
                TlsUtilities.WriteUint16((int)outerExtOutput.Length + 1, extOutput);
                TlsUtilities.WriteOpaque8(outerExtOutput.ToArray(), extOutput);
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
