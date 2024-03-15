using Org.BouncyCastle.Crypto.Hpke;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Ech
{
    public class ECHConfig
    {
        public X25519PublicKeyParameters PublicKey { get; set; }
        public byte[] Raw { get; set; }
        public ushort Version { get; set; }
        public byte ConfigId { get; set; }
        public byte[] RawPublicName { get; set; }
        public byte[] RawPublicKey { get; set; }
        public ushort KemId { get; set; }
        public List<HpkeSymmetricCipherSuite> Suites { get; set; } = [];
        public byte MaxNameLen { get; set; }
        public byte[] IgnoredExtensions { get; set; }

        public HPKEContextWithEncapsulation SetupSealer()
        {
            byte[] info = [.."tls ech"u8, 0, ..Raw];

            byte[] seed = [117, 200, 83, 30, 45, 18, 157, 218, 108, 42, 215, 129, 67, 248, 104, 105, 4, 240, 18, 244, 114, 145, 149, 171, 107, 207, 61, 18, 98, 48, 225, 109];

            var hpke = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
            var pair = hpke.DeriveKeyPair(seed);
            var ctx = hpke.SetupBaseS(PublicKey, info, pair);

            return ctx;
        }

        public static List<ECHConfig> Parse(string base64) => Parse(Convert.FromBase64String(base64));

        public static List<ECHConfig> Parse(byte[] raw)
        {
            var configs = new List<ECHConfig>();

            using var ms = new MemoryStream(raw);

            if (ms.Length < 2)
                throw new Exception("Error parsing configs");

            ushort totalLength = (ushort)TlsUtilities.ReadUint16(ms);

            raw = raw[2..];

            while (ms.Position < ms.Length)
            {
                var start = ms.Position;

                var config = new ECHConfig
                {
                    Version = (ushort)TlsUtilities.ReadUint16(ms)
                };

                var contentLength = (ushort)TlsUtilities.ReadUint16(ms);

                var index = (int)(ms.Position + contentLength - start);

                config.Raw = raw[..index];
                raw = raw[index..];

                if (config.Version != 0xfe0d)
                {
                    Console.WriteLine("Invalid config version");
                    continue;
                }

                config.ConfigId = (byte)TlsUtilities.ReadUint8(ms);
                config.KemId = (ushort)TlsUtilities.ReadUint16(ms);

                config.RawPublicKey = TlsUtilities.ReadOpaque16(ms);
                config.PublicKey = new X25519PublicKeyParameters(config.RawPublicKey);

                var suitesLength = (ushort)TlsUtilities.ReadUint16(ms);

                for (int i = 0; i < suitesLength; i += 4)
                {
                    var kdfId = (ushort)TlsUtilities.ReadUint16(ms);
                    var aeadId = (ushort)TlsUtilities.ReadUint16(ms);

                    config.Suites.Add(new(kdfId, aeadId));
                }

                config.MaxNameLen = (byte)TlsUtilities.ReadUint8(ms);
                config.RawPublicName = TlsUtilities.ReadOpaque8(ms);
                config.IgnoredExtensions = TlsUtilities.ReadOpaque16(ms);

                configs.Add(config);
            }

            return configs;
        }
    }

    public class HpkeSymmetricCipherSuite(ushort kdfId, ushort aeadId)
    {
        public ushort KdfId { get; set; } = kdfId;

        public ushort AeadId { get; set; } = aeadId;
    }
}
