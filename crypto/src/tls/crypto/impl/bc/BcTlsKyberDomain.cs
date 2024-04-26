using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsKyberDomain : TlsKEMDomain
    {
        public static KyberParameters GetKyberParameters(TlsKEMConfig kemConfig)
        {
            switch (kemConfig.GetKEMNamedGroup())
            {
                case NamedGroup.kyber512:
                    return KyberParameters.kyber512;
                case NamedGroup.kyber768:
                    return KyberParameters.kyber768;
                case NamedGroup.kyber1024:
                    return KyberParameters.kyber1024;
                default:
                    return null;
            }
        }

        protected readonly BcTlsCrypto crypto;
        protected readonly TlsKEMConfig kemConfig;
        protected readonly KyberParameters kyberParameters;

        public TlsKEMConfig TlsKEMConfig => kemConfig;

        public BcTlsKyberDomain(BcTlsCrypto crypto, TlsKEMConfig kemConfig)
        {
            this.crypto = crypto;
            this.kemConfig = kemConfig;
            this.kyberParameters = GetKyberParameters(kemConfig);
        }

        public TlsAgreement CreateKEM()
        {
            return new BcTlsKyber(this);
        }

        public KyberPublicKeyParameters DecodePublicKey(byte[] encoding)
        {
            return new KyberPublicKeyParameters(kyberParameters, encoding);
        }

        public byte[] EncodePublicKey(KyberPublicKeyParameters kyberPublicKeyParameters)
        {
            return kyberPublicKeyParameters.GetEncoded();
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
            keyPairGenerator.Init(new KyberKeyGenerationParameters(crypto.SecureRandom, kyberParameters));
            return keyPairGenerator.GenerateKeyPair();
        }

        public TlsSecret AdoptLocalSecret(byte[] secret)
        {
            return crypto.AdoptLocalSecret(secret);
        }

        public ISecretWithEncapsulation EnCap(KyberPublicKeyParameters peerPublicKey)
        {
            KyberKemGenerator kemGen = new KyberKemGenerator(crypto.SecureRandom);
            return kemGen.GenerateEncapsulated(peerPublicKey);
        }

        public byte[] DeCap(KyberPrivateKeyParameters kyberPrivateKeyParameters, byte[] cipherText)
        {
            KyberKemExtractor kemExtract = new KyberKemExtractor(kyberPrivateKeyParameters);
            byte[] secret = kemExtract.Decapsulate(cipherText);
            return secret;
        }
    }


}
