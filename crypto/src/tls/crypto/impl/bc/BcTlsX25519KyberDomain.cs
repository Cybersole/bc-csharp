using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsX25519KyberDomain : TlsKEMDomain
    {
        protected readonly BcTlsKyberDomain kyberDomain;
        protected readonly BcTlsCrypto crypto;

        public BcTlsX25519KyberDomain(BcTlsCrypto crypto, TlsKEMConfig kemConfig)
        {
            this.kyberDomain = new BcTlsKyberDomain(crypto, kemConfig);
            this.crypto = crypto;
        }

        public TlsAgreement CreateKEM()
        {
            return new BcTlsX25519Kyber(this);
        }

        public BcTlsKyberDomain GetKyberDomain()
        {
            return kyberDomain;
        }

        public byte[] GenerateX25519PrivateKey()
        {
            byte[] privateKey = new byte[X25519.ScalarSize];
            crypto.SecureRandom.NextBytes(privateKey);
            return privateKey;
        }

        public byte[] GetX25519PublicKey(byte[] privateKey)
        {
            byte[] publicKey = new byte[X25519.PointSize];
            X25519.ScalarMultBase(privateKey, 0, publicKey, 0);
            return publicKey;
        }

        public int GetX25519PublicKeyByteLength()
        {
            return X25519.PointSize;
        }

        public byte[] CalculateX25519Secret(byte[] privateKey, byte[] peerPublicKey)
        {
            byte[] secret = new byte[X25519.PointSize];
            if (!X25519.CalculateAgreement(privateKey, 0, peerPublicKey, 0, secret, 0))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            return secret;
        }
    }




}
