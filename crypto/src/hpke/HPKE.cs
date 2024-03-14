using Org.BouncyCastle.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Hpke
{
    public class HPKE
    {
        // modes
        public const byte mode_base = 0x00;
        public const byte mode_psk = 0x01;
        public const byte mode_auth = 0x02;
        public const byte mode_auth_psk = 0x03;
        // kems
        public const short kem_P256_SHA256 = 16;
        public const short kem_P384_SHA348 = 17;
        public const short kem_P521_SHA512 = 18;
        public const short kem_X25519_SHA256 = 32;
        public const short kem_X448_SHA512 = 33;
        // kdfs
        public const short kdf_HKDF_SHA256 = 0x0001;
        public const short kdf_HKDF_SHA384 = 0x0002;
        public const short kdf_HKDF_SHA512 = 0x0003;
        // aeads
        public const short aead_AES_GCM128 = 0x0001;
        public const short aead_AES_GCM256 = 0x0002;
        public const short aead_CHACHA20_POLY1305 = 0x0003;
        public const short aead_EXPORT_ONLY = -1;

        private readonly byte[] default_psk = null;
        private readonly byte[] default_psk_id = null;
        private readonly byte mode;
        private readonly short kemId;
        private readonly short kdfId;
        private readonly short aeadId;
        private readonly DHKEM dhkem;
        private readonly HKDF hkdf;
        short Nk;

        public HPKE(byte mode, short kemId, short kdfId, short aeadId)
        {
            this.mode = mode;
            this.kemId = kemId;
            this.kdfId = kdfId;
            this.aeadId = aeadId;
            this.hkdf = new HKDF(kdfId);
            this.dhkem = new DHKEM(kemId);

            if (aeadId == aead_AES_GCM128)
            {
                Nk = 16;
            }
            else
            {
                Nk = 32;
            }
        }

        public virtual int GetEncSize()
        {
            switch (kemId)
            {
                case HPKE.kem_P256_SHA256:
                    return 65;
                case HPKE.kem_P384_SHA348:
                    return 97;
                case HPKE.kem_P521_SHA512:
                    return 133;
                case HPKE.kem_X25519_SHA256:
                    return 32;
                case HPKE.kem_X448_SHA512:
                    return 56;
                default:
                    throw new ArgumentException("invalid kem id");
            }
        }

        public virtual short GetAeadId()
        {
            return aeadId;
        }

        private void VerifyPSKInputs(byte mode, byte[] psk, byte[] pskid)
        {
            bool got_psk = (!Arrays.AreEqual(psk, default_psk));
            bool got_psk_id = (!Arrays.AreEqual(pskid, default_psk_id));
            if (got_psk != got_psk_id)
            {
                throw new ArgumentException("Inconsistent PSK inputs");
            }

            if (got_psk && (mode % 2 == 0))
            {
                throw new ArgumentException("PSK input provided when not needed");
            }

            if ((!got_psk) && (mode % 2 == 1))
            {
                throw new ArgumentException("Missing required PSK input");
            }
        }

        private HPKEContext KeySchedule(byte mode, byte[] sharedSecret, byte[] info, byte[] psk, byte[] pskid)
        {
            VerifyPSKInputs(mode, psk, pskid);
            byte[] suiteId = Arrays.ConcatenateAll(Strings.ToByteArray("HPKE"), Pack.ShortToBigEndian(kemId), Pack.ShortToBigEndian(kdfId), Pack.ShortToBigEndian(aeadId));
            byte[] pskidHash = hkdf.LabeledExtract(null, suiteId, "psk_id_hash", pskid);
            byte[] infoHash = hkdf.LabeledExtract(null, suiteId, "info_hash", info);
            byte[] modeArray = new byte[1];
            modeArray[0] = mode;
            byte[] keyScheduleContext = Arrays.ConcatenateAll(modeArray, pskidHash, infoHash);
            byte[] secret = hkdf.LabeledExtract(sharedSecret, suiteId, "secret", psk);
            byte[] key = hkdf.LabeledExpand(secret, suiteId, "key", keyScheduleContext, Nk);
            byte[] base_nonce = hkdf.LabeledExpand(secret, suiteId, "base_nonce", keyScheduleContext, 12); //Nn
            byte[] exporter_secret = hkdf.LabeledExpand(secret, suiteId, "exp", keyScheduleContext, hkdf.GetHashSize()); //todo Nk*2 with replace hash digest size
            return new HPKEContext(new AEAD(aeadId, key, base_nonce), hkdf, exporter_secret, suiteId);
        }

        public virtual AsymmetricCipherKeyPair GeneratePrivateKey()
        {
            return dhkem.GeneratePrivateKey();
        }

        public virtual byte[] SerializePublicKey(AsymmetricKeyParameter pk)
        {
            return dhkem.SerializePublicKey(pk);
        }

        public virtual byte[] SerializePrivateKey(AsymmetricKeyParameter sk)
        {
            return dhkem.SerializePrivateKey(sk);
        }

        public virtual AsymmetricKeyParameter DeserializePublicKey(byte[] pkEncoded)
        {
            return dhkem.DeserializePublicKey(pkEncoded);
        }

        public virtual AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
        {
            return dhkem.DeserializePrivateKey(skEncoded, pkEncoded);
        }

        public virtual AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
        {
            return dhkem.DeriveKeyPair(ikm);
        }

        public virtual (byte[], byte[]) SendExport(AsymmetricKeyParameter pkR, byte[] info, byte[] exporterContext, int L, byte[] psk, byte[] pskId, AsymmetricCipherKeyPair skS)
        {
            HPKEContextWithEncapsulation ctx;

            switch (mode)
            {
                case mode_base:
                    ctx = SetupBaseS(pkR, info);
                    break;
                case mode_auth:
                    ctx = SetupAuthS(pkR, info, skS);
                    break;
                case mode_psk:
                    ctx = SetupPSKS(pkR, info, psk, pskId);
                    break;
                case mode_auth_psk:
                    ctx = SetupAuthPSKS(pkR, info, psk, pskId, skS);
                    break;
                default:
                    throw new InvalidOperationException("Unknown mode");
            }

            // ct and enc
            return (ctx.GetEncapsulation(), ctx.Export(exporterContext, L));
        }

        public virtual byte[] ReceiveExport(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] exporterContext, int L, byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
        {
            HPKEContext ctx;
            switch (mode)
            {
                case mode_base:
                    ctx = SetupBaseR(enc, skR, info);
                    break;
                case mode_auth:
                    ctx = SetupAuthR(enc, skR, info, pkS);
                    break;
                case mode_psk:
                    ctx = SetupPSKR(enc, skR, info, psk, pskId);
                    break;
                case mode_auth_psk:
                    ctx = SetupAuthPSKR(enc, skR, info, psk, pskId, pkS);
                    break;
                default:
                    throw new InvalidOperationException("Unknown mode");
            }

            return ctx.Export(exporterContext, L);
        }

        public virtual (byte[], byte[]) Seal(AsymmetricKeyParameter pkR, byte[] info, byte[] aad, byte[] pt, byte[] psk, byte[] pskId, AsymmetricCipherKeyPair skS)
        {
            HPKEContextWithEncapsulation ctx;

            switch (mode)
            {
                case mode_base:
                    ctx = SetupBaseS(pkR, info);
                    break;
                case mode_auth:
                    ctx = SetupAuthS(pkR, info, skS);
                    break;
                case mode_psk:
                    ctx = SetupPSKS(pkR, info, psk, pskId);
                    break;
                case mode_auth_psk:
                    ctx = SetupAuthPSKS(pkR, info, psk, pskId, skS);
                    break;
                default:
                    throw new InvalidOperationException("Unknown mode");
            }

            // ct and enc
            return (ctx.Seal(aad, pt), ctx.GetEncapsulation());
        }

        public virtual byte[] Open(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] aad, byte[] ct, byte[] psk, byte[] pskId, AsymmetricKeyParameter pkS)
        {
            HPKEContext ctx;
            switch (mode)
            {
                case mode_base:
                    ctx = SetupBaseR(enc, skR, info);
                    break;
                case mode_auth:
                    ctx = SetupAuthR(enc, skR, info, pkS);
                    break;
                case mode_psk:
                    ctx = SetupPSKR(enc, skR, info, psk, pskId);
                    break;
                case mode_auth_psk:
                    ctx = SetupAuthPSKR(enc, skR, info, psk, pskId, pkS);
                    break;
                default:
                    throw new InvalidOperationException("Unknown mode");
            }

            return ctx.Open(aad, ct);
        }

        public virtual HPKEContextWithEncapsulation SetupBaseS(AsymmetricKeyParameter pkR, byte[] info)
        {
            (byte[] sharedSecret, byte[] enc) = dhkem.Encap(pkR); // sharedSecret, enc
            HPKEContext ctx = KeySchedule(mode_base, sharedSecret, info, default_psk, default_psk_id);

            return new HPKEContextWithEncapsulation(ctx, enc);
        }

        // Variant of setupBaseS() where caller can provide their own ephemeral key pair.
        // This should only be used to validate test vectors.
        public virtual HPKEContextWithEncapsulation SetupBaseS(AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair kpE)
        {
            (byte[] sharedSecret, byte[] enc) = dhkem.Encap(pkR, kpE); // sharedSecret, enc
            HPKEContext ctx = KeySchedule(mode_base, sharedSecret, info, default_psk, default_psk_id);

            return new HPKEContextWithEncapsulation(ctx, enc);
        }

        public virtual HPKEContext SetupBaseR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info)
        {
            byte[] sharedSecret = dhkem.Decap(enc, skR);
            return KeySchedule(mode_base, sharedSecret, info, default_psk, default_psk_id);
        }

        public virtual HPKEContextWithEncapsulation SetupPSKS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk, byte[] psk_id)
        {
            (byte[] sharedSecret, byte[] enc) = dhkem.Encap(pkR); // sharedSecret, enc
            HPKEContext ctx = KeySchedule(mode_psk, sharedSecret, info, psk, psk_id);
            return new HPKEContextWithEncapsulation(ctx, enc);
        }

        public virtual HPKEContext SetupPSKR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk, byte[] psk_id)
        {
            byte[] sharedSecret = dhkem.Decap(enc, skR);
            return KeySchedule(mode_psk, sharedSecret, info, psk, psk_id);
        }

        public virtual HPKEContextWithEncapsulation SetupAuthS(AsymmetricKeyParameter pkR, byte[] info, AsymmetricCipherKeyPair skS)
        {
            (byte[] sharedSecret, byte[] enc) = dhkem.AuthEncap(pkR, skS);
            HPKEContext ctx = KeySchedule(mode_auth, sharedSecret, info, default_psk, default_psk_id);
            return new HPKEContextWithEncapsulation(ctx, enc);
        }

        public virtual HPKEContext SetupAuthR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, AsymmetricKeyParameter pkS)
        {
            byte[] sharedSecret = dhkem.AuthDecap(enc, skR, pkS);
            return KeySchedule(mode_auth, sharedSecret, info, default_psk, default_psk_id);
        }

        public virtual HPKEContextWithEncapsulation SetupAuthPSKS(AsymmetricKeyParameter pkR, byte[] info, byte[] psk, byte[] psk_id, AsymmetricCipherKeyPair skS)
        {
            (byte[] sharedSecret, byte[] enc) = dhkem.AuthEncap(pkR, skS);
            HPKEContext ctx = KeySchedule(mode_auth_psk, sharedSecret, info, psk, psk_id);
            return new HPKEContextWithEncapsulation(ctx, enc);
        }

        public virtual HPKEContext SetupAuthPSKR(byte[] enc, AsymmetricCipherKeyPair skR, byte[] info, byte[] psk, byte[] psk_id, AsymmetricKeyParameter pkS)
        {
            byte[] sharedSecret = dhkem.AuthDecap(enc, skR, pkS);
            return KeySchedule(mode_auth_psk, sharedSecret, info, psk, psk_id);
        }
    }
}