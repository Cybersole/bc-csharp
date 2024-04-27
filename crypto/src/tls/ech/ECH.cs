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

        public static readonly int[] UncompressedExtensions = [ExtensionType.ech, ExtensionType.server_name, ExtensionType.supported_versions];
        public static readonly int[] RequiredExtensions = [ExtensionType.supported_groups, ExtensionType.key_share, ExtensionType.application_layer_protocol_negotiation, ExtensionType.signature_algorithms, ..UncompressedExtensions];

        public static (ClientHello, ClientHello) OfferECH(ClientHello hello, ECHConfig config)
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

                hello.Extensions[ExtensionECH] = echGrease.ToBytes();

                return (null, hello);
            }

            var ctx = config.SetupSealer();

            // Setup an empty ECH outer value
            var ech = new ECHClientOuter();
            ech.Handle.Enc = ctx.GetEncapsulation();
            ech.Handle.Suite = config.Suites[0];
            ech.Handle.ConfigId = config.ConfigId;

            // Only include TLS 1.3 extensions and order by the ones that will be compressed first
            var innerExtensions = hello.Extensions.Where(e => RequiredExtensions.Contains(e.Key)).OrderBy(e => CompressExtension(e.Key)).ToDictionary();

            // Set ECH to inner variant and TLS version to strict 1.3
            innerExtensions[ExtensionECH] = [ECHClientHelloInnerVariant];
            innerExtensions[ExtensionType.supported_versions] = TlsExtensionsUtilities
                .CreateSupportedVersionsExtensionClient([ProtocolVersion.TLSv13]);

            // Create and encode the new HelloInner
            var innerHello = new ClientHello(hello.Version, hello.Random, hello.SessionID,
                hello.Cookie, hello.CipherSuites, innerExtensions, hello.BindersSize);

            var serverName = hello.Extensions[ExtensionType.server_name];
            var echInner = EncodeHelloInner(innerHello, serverName.Length, config.MaxNameLen);
            var cipherLen = echInner.Length + 16;

            // Remove extensions from HelloOuter if they have not been compressed and are the same as HelloInner
            foreach (var extension in hello.Extensions)
                if (!CompressExtension(extension.Key) && !UncompressedExtensions.Contains(extension.Key))
                    hello.Extensions.Remove(extension.Key);

            // Set the client facing server SNI value and placeholder ECH
            hello.Extensions[ExtensionType.server_name] = TlsExtensionsUtilities
                .CreateServerNameExtensionClient([new ServerName(0, config.RawPublicName)]);
            hello.Extensions[ExtensionECH] = ech.ToBytes();

            // Encode HelloOuter and set the encrypted_client_hello extension on HelloOuter
            var echOutter = EncodeHelloOuterAAD(hello, (uint)cipherLen);

            ech.Payload = ctx.Seal(echOutter, echInner);

            hello.Extensions[ExtensionECH] = ech.ToBytes();

            return (innerHello, hello);
        }

        // For now don't encrypt extensions other than the required ones (so compress all other).
        // This is what Chrome seems to do.
        public static bool CompressExtension(int extension) => !UncompressedExtensions.Contains(extension);

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
