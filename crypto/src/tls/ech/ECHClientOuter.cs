using Org.BouncyCastle.Tls;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Ech
{
    public class ECHClientOuter
    {
        public byte[] Raw { get; set; }

        public byte[] Payload { get; set; }

        public ECHContext Handle { get; set; }

        public ECHClientOuter()
        {
            Handle = new();
            Payload = [];
        }

        public static ECHClientOuter FromBytes(byte[] bytes)
        {
            var input = new MemoryStream(bytes);

            var ech = new ECHClientOuter();
            var variant = TlsUtilities.ReadUint8(input);

            var kdfId = (ushort)TlsUtilities.ReadUint16(input);
            var aeadId = (ushort)TlsUtilities.ReadUint16(input);

            ech.Handle.Suite = new HpkeSymmetricCipherSuite(kdfId, aeadId);
            ech.Handle.ConfigId = (byte)TlsUtilities.ReadUint8(input);
            ech.Handle.Enc = TlsUtilities.ReadOpaque16(input);

            ech.Handle.Raw = bytes[1..(int)input.Position];

            ech.Payload = TlsUtilities.ReadOpaque16(input);

            return ech;
        }

        public byte[] ToBytes()
        {
            using var stream = new MemoryStream();

            TlsUtilities.WriteUint8(ECH.ECHClientHelloOuterVariant, stream);

            stream.Write(Handle.ToBytes());

            TlsUtilities.WriteOpaque16(Payload, stream);

            return stream.ToArray();
        }
    }

    public class ECHContext
    {
        public byte[] Raw { get; set; }

        public byte[] Enc { get; set; }

        public byte ConfigId { get; set; }

        public HpkeSymmetricCipherSuite Suite { get; set; }

        public byte[] ToBytes()
        {
            using var stream = new MemoryStream();

            TlsUtilities.WriteUint16(Suite.KdfId, stream);
            TlsUtilities.WriteUint16(Suite.AeadId, stream);
            TlsUtilities.WriteUint8(ConfigId, stream);

            TlsUtilities.WriteOpaque16(Enc, stream);

            return stream.ToArray();
        }
    }
}
