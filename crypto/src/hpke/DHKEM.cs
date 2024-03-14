using Org.BouncyCastle.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Agreement;
using System;
using Org.BouncyCastle.Math.EC.Custom.Sec;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Hpke
{
    public class DHKEM
    {
        private IAsymmetricCipherKeyPairGenerator kpGen;
        private IBasicAgreement agreement;

        // kem ids
        private readonly short kemId;
        private HKDF hkdf;
        private byte bitmask;
        private int Nsk;
        private int Nsecret;
        ECDomainParameters domainParams;

        public DHKEM(short kemid)
        {
            this.kemId = kemid;
            ECCurve curve;

            switch (kemid)
            {
                case HPKE.kem_P256_SHA256:
                    this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA256);
                    curve = new SecP256R1Curve();
                    domainParams = new ECDomainParameters(curve, curve.CreatePoint(new BigInteger(1, Hex.Decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")), new BigInteger(1, Hex.Decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))), curve.Order, curve.Cofactor, Hex.Decode("c49d360886e704936a6678e1139d26b7819f7e90"));
                    this.agreement = new ECDHCBasicAgreement();
                    bitmask = (byte)0xff;
                    Nsk = 32;
                    Nsecret = 32;
                    this.kpGen = new ECKeyPairGenerator();
                    this.kpGen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
                    break;
                case HPKE.kem_P384_SHA348:
                    this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA384);
                    curve = new SecP384R1Curve();
                    domainParams = new ECDomainParameters(curve, curve.CreatePoint(new BigInteger(1, Hex.Decode("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7")), new BigInteger(1, Hex.Decode("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"))), curve.Order, curve.Cofactor, Hex.Decode("a335926aa319a27a1d00896a6773a4827acdac73"));
                    this.agreement = new ECDHCBasicAgreement();
                    bitmask = (byte)0xff;
                    Nsk = 48;
                    Nsecret = 48;
                    this.kpGen = new ECKeyPairGenerator();
                    this.kpGen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
                    break;
                case HPKE.kem_P521_SHA512:
                    this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA512);
                    curve = new SecP521R1Curve();
                    domainParams = new ECDomainParameters(curve, curve.CreatePoint(new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16), new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)), curve.Order, curve.Cofactor, Hex.Decode("d09e8800291cb85396cc6717393284aaa0da64ba"));
                    this.agreement = new ECDHCBasicAgreement();
                    bitmask = 0x01;
                    Nsk = 66;
                    Nsecret = 64;
                    this.kpGen = new ECKeyPairGenerator();
                    this.kpGen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
                    break;
                case HPKE.kem_X25519_SHA256:
                    this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA256);
                    this.agreement = new XDHBasicAgreement();
                    Nsecret = 32;
                    Nsk = 32;
                    this.kpGen = new X25519KeyPairGenerator();
                    this.kpGen.Init(new X25519KeyGenerationParameters(new SecureRandom()));
                    break;
                case HPKE.kem_X448_SHA512:
                    this.hkdf = new HKDF(HPKE.kdf_HKDF_SHA512);
                    this.agreement = new XDHBasicAgreement();
                    Nsecret = 64;
                    Nsk = 56;
                    this.kpGen = new X448KeyPairGenerator();
                    this.kpGen.Init(new X448KeyGenerationParameters(new SecureRandom()));
                    break;
                default:
                    throw new ArgumentException("invalid kem id");
            }
        }

        public virtual byte[] SerializePublicKey(AsymmetricKeyParameter key)
        {
            switch (kemId)
            {
                case HPKE.kem_P256_SHA256:
                case HPKE.kem_P384_SHA348:
                case HPKE.kem_P521_SHA512:
                    return ((ECPublicKeyParameters)key).Q.GetEncoded(false);
                case HPKE.kem_X448_SHA512:
                    return ((X448PublicKeyParameters)key).GetEncoded();
                case HPKE.kem_X25519_SHA256:
                    return ((X25519PublicKeyParameters)key).GetEncoded();
                default:
                    throw new InvalidOperationException("invalid kem id");
            }
        }

        public virtual byte[] SerializePrivateKey(AsymmetricKeyParameter key)
        {
            switch (kemId)
            {
                case HPKE.kem_P256_SHA256:
                case HPKE.kem_P384_SHA348:
                case HPKE.kem_P521_SHA512:
                    return FormatBigIntegerBytes(((ECPrivateKeyParameters)key).D.ToByteArray(), Nsk);
                case HPKE.kem_X448_SHA512:
                    return ((X448PrivateKeyParameters)key).GetEncoded();
                case HPKE.kem_X25519_SHA256:
                    return ((X25519PrivateKeyParameters)key).GetEncoded();
                default:
                    throw new InvalidOperationException("invalid kem id");
            }
        }

        public virtual AsymmetricKeyParameter DeserializePublicKey(byte[] encoded)
        {
            switch (kemId)
            {
                case HPKE.kem_P256_SHA256:
                case HPKE.kem_P384_SHA348:
                case HPKE.kem_P521_SHA512:
                    ECPoint G = domainParams.Curve.DecodePoint(encoded);
                    return new ECPublicKeyParameters(G, domainParams);
                case HPKE.kem_X448_SHA512:
                    return new X448PublicKeyParameters(encoded);
                case HPKE.kem_X25519_SHA256:
                    return new X25519PublicKeyParameters(encoded);
                default:
                    throw new InvalidOperationException("invalid kem id");
            }
        }

        public virtual AsymmetricCipherKeyPair DeserializePrivateKey(byte[] skEncoded, byte[] pkEncoded)
        {
            AsymmetricKeyParameter pubParam = null;
            if (pkEncoded != null)
            {
                pubParam = DeserializePublicKey(pkEncoded);
            }

            switch (kemId)
            {
                case HPKE.kem_P256_SHA256:
                case HPKE.kem_P384_SHA348:
                case HPKE.kem_P521_SHA512:
                    BigInteger d = new BigInteger(1, skEncoded);
                    ECPrivateKeyParameters ec = new ECPrivateKeyParameters(d, domainParams);
                    if (pubParam == null)
                    {
                        ECPoint Q = new FixedPointCombMultiplier().Multiply(domainParams.G, ((ECPrivateKeyParameters)ec).D);
                        pubParam = new ECPublicKeyParameters(Q, domainParams);
                    }

                    return new AsymmetricCipherKeyPair(pubParam, ec);
                case HPKE.kem_X448_SHA512:
                    X448PrivateKeyParameters x448 = new X448PrivateKeyParameters(skEncoded);
                    if (pubParam == null)
                    {
                        pubParam = x448.GeneratePublicKey();
                    }

                    return new AsymmetricCipherKeyPair(pubParam, x448);
                case HPKE.kem_X25519_SHA256:
                    X25519PrivateKeyParameters x25519 = new X25519PrivateKeyParameters(skEncoded);
                    if (pubParam == null)
                    {
                        pubParam = x25519.GeneratePublicKey();
                    }

                    return new AsymmetricCipherKeyPair(pubParam, x25519);
                default:
                    throw new InvalidOperationException("invalid kem id");
            }
        }

        private bool ValidateSk(BigInteger d)
        {
            /*BigInteger n = domainParams.N;
            int nBitLength = n.BitLength;
            int minWeight = nBitLength >>> 2;
            if (d.CompareTo(BigInteger.ValueOf(1)) < 0 || (d.CompareTo(n) >= 0))
            {
                return false;
            }

            if (WNafUtil.GetNafWeight(d) < minWeight)
            {
                return false;
            }*/

            return true;
        }

        public virtual AsymmetricCipherKeyPair GeneratePrivateKey()
        {
            return kpGen.GenerateKeyPair(); // todo: can be replaced with deriveKeyPair(random)
        }

        public virtual AsymmetricCipherKeyPair DeriveKeyPair(byte[] ikm)
        {

            //        if (ikm.length < Nsk)
            //        {
            //            throw new IllegalArgumentException("input keying material should have length at least " + Nsk + " bytes");
            //        }

            byte[] suiteID = Arrays.Concatenate(Strings.ToByteArray("KEM"), Pack.ShortToBigEndian(kemId));
            switch (kemId)
            {
                /*case HPKE.kem_P256_SHA256:
                case HPKE.kem_P384_SHA348:
                case HPKE.kem_P521_SHA512:
                    byte[] dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                    int counter = 0;
                    byte[] counterArray = new byte[1];
                    while (true)
                    {
                        if (counter > 255)
                        {
                            throw new InvalidOperationException("DeriveKeyPairError");
                        }

                        counterArray[0] = (byte)counter;
                        byte[] bytes = hkdf.LabeledExpand(dkp_prk, suiteID, "candidate", counterArray, Nsk);
                        bytes[0] = (byte)(bytes[0] & bitmask);

                        // generating keypair
                        BigInteger d = new BigInteger(1, bytes);
                        if (ValidateSk(d))
                        {
                            ECPoint Q = new FixedPointCombMultiplier().Multiply(domainParams.G, d);
                            ECPrivateKeyParameters sk = new ECPrivateKeyParameters(d, domainParams);
                            ECPublicKeyParameters pk = new ECPublicKeyParameters(Q, domainParams);
                            return new AsymmetricCipherKeyPair(pk, sk);
                        }

                        counter++;
                    }*/

                case HPKE.kem_X448_SHA512:
                    var dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                    byte[] x448sk = hkdf.LabeledExpand(dkp_prk, suiteID, "sk", null, Nsk);
                    X448PrivateKeyParameters x448params = new X448PrivateKeyParameters(x448sk);
                    return new AsymmetricCipherKeyPair(x448params.GeneratePublicKey(), x448params);

                case HPKE.kem_X25519_SHA256:
                    dkp_prk = hkdf.LabeledExtract(null, suiteID, "dkp_prk", ikm);
                    byte[] skBytes = hkdf.LabeledExpand(dkp_prk, suiteID, "sk", null, Nsk);
                    X25519PrivateKeyParameters sk = new X25519PrivateKeyParameters(skBytes);
                    return new AsymmetricCipherKeyPair(sk.GeneratePublicKey(), sk);

                default:
                    throw new InvalidOperationException("invalid kem id");
            }
        }

        public virtual (byte[], byte[]) Encap(AsymmetricKeyParameter pkR)
        {
            return Encap(pkR, kpGen.GenerateKeyPair()); // todo: can be replaced with deriveKeyPair(random)
        }

        public virtual (byte[], byte[]) Encap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpE)
        {
            //DH
            agreement.Init(kpE.Private);

            byte[] temp = agreement.CalculateAgreement(pkR).ToByteArray();
            byte[] secret = FormatBigIntegerBytes(temp, agreement.GetFieldSize());
            byte[] enc = SerializePublicKey(kpE.Public);
            byte[] pkRm = SerializePublicKey(pkR);
            byte[] KEMContext = Arrays.Concatenate(enc, pkRm);
            byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);

            return (sharedSecret, enc);
        }

        public virtual byte[] Decap(byte[] enc, AsymmetricCipherKeyPair kpR)
        {
            AsymmetricKeyParameter pkE = DeserializePublicKey(enc);

            //DH
            agreement.Init(kpR.Private);
            byte[] temp = agreement.CalculateAgreement(pkE).ToByteArray(); // add leading zeros
            byte[] secret = FormatBigIntegerBytes(temp, agreement.GetFieldSize());
            byte[] pkRm = SerializePublicKey(kpR.Public);
            byte[] KEMContext = Arrays.Concatenate(enc, pkRm);
            byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);

            return sharedSecret;
        }

        public virtual (byte[], byte[]) AuthEncap(AsymmetricKeyParameter pkR, AsymmetricCipherKeyPair kpS)
        {
            AsymmetricCipherKeyPair kpE = kpGen.GenerateKeyPair(); // todo: can be replaced with deriveKeyPair(random)

            // DH(skE, pkR)
            agreement.Init(kpE.Private);
            byte[] temp = agreement.CalculateAgreement(pkR).ToByteArray();
            byte[] secret1 = FormatBigIntegerBytes(temp, agreement.GetFieldSize());

            // DH(skS, pkR)
            agreement.Init(kpS.Private);
            temp = agreement.CalculateAgreement(pkR).ToByteArray();
            byte[] secret2 = FormatBigIntegerBytes(temp, agreement.GetFieldSize());
            byte[] secret = Arrays.Concatenate(secret1, secret2);
            byte[] enc = SerializePublicKey(kpE.Public);
            byte[] pkRm = SerializePublicKey(pkR);
            byte[] pkSm = SerializePublicKey(kpS.Public);
            byte[] KEMContext = Arrays.ConcatenateAll(enc, pkRm, pkSm);
            byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);

            return (sharedSecret, enc);
        }

        public virtual byte[] AuthDecap(byte[] enc, AsymmetricCipherKeyPair kpR, AsymmetricKeyParameter pkS)
        {
            AsymmetricKeyParameter pkE = DeserializePublicKey(enc);

            // DH(skR, pkE)
            agreement.Init(kpR.Private);
            byte[] temp = agreement.CalculateAgreement(pkE).ToByteArray(); // add leading zeros
            byte[] secret1 = FormatBigIntegerBytes(temp, agreement.GetFieldSize());

            // DH(skR, pkS)
            agreement.Init(kpR.Private);
            temp = agreement.CalculateAgreement(pkS).ToByteArray();
            byte[] secret2 = FormatBigIntegerBytes(temp, agreement.GetFieldSize());
            byte[] secret = Arrays.Concatenate(secret1, secret2);
            byte[] pkRm = SerializePublicKey(kpR.Public);
            byte[] pkSm = SerializePublicKey(pkS);
            byte[] KEMContext = Arrays.ConcatenateAll(enc, pkRm, pkSm);
            byte[] sharedSecret = ExtractAndExpand(secret, KEMContext);
            return sharedSecret;
        }

        private byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
        {
            byte[] suiteID = Arrays.Concatenate(Strings.ToByteArray("KEM"), Pack.ShortToBigEndian(kemId));
            byte[] eae_prk = hkdf.LabeledExtract(null, suiteID, "eae_prk", dh);
            byte[] sharedSecret = hkdf.LabeledExpand(eae_prk, suiteID, "shared_secret", kemContext, Nsecret);
            return sharedSecret;
        }

        private byte[] FormatBigIntegerBytes(byte[] bigIntBytes, int outputSize)
        {
            byte[] output = new byte[outputSize];
            if (bigIntBytes.Length <= outputSize)
            {
                Array.Copy(bigIntBytes, 0, output, outputSize - bigIntBytes.Length, bigIntBytes.Length);
            }
            else
            {
                Array.Copy(bigIntBytes, bigIntBytes.Length - outputSize, output, 0, outputSize);
            }

            return output;
        }
    }
}