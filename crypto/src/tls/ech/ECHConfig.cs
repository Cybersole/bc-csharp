using Org.BouncyCastle.Crypto.Hpke;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;

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
            byte[] info = Raw != null ? [.."tls ech"u8, 0, ..Raw] : null;
            byte[] seed = new byte[32];

            Random.Shared.NextBytes(seed);

            var hpke = new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
            var pair = hpke.DeriveKeyPair(seed);
            var ctx = hpke.SetupBaseS(PublicKey, info, pair);

            return ctx;
        }

        public static ECHConfig GetGrease()
        {
            byte[] dummyX25519PublicKey = [143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216, 81, 163, 222, 52, 211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244];

            return new()
            {
                ConfigId = (byte)Random.Shared.Next(0, 255),
                KemId = 0x20,
                Suites =
                [
                    new HpkeSymmetricCipherSuite(0x01, 0x01)
                ],
                RawPublicKey = dummyX25519PublicKey,
                PublicKey = new X25519PublicKeyParameters(dummyX25519PublicKey)
            };
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
