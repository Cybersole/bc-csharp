using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public class BcTlsX25519Kyber : TlsAgreement
    {
        protected readonly BcTlsX25519KyberDomain domain;

        protected AsymmetricCipherKeyPair kyberLocalKeyPair;
        protected KyberPublicKeyParameters kyberPeerPublicKey;
        protected byte[] x25519PrivateKey;
        protected byte[] x25519PeerPublicKey;

        protected byte[] kyberCiphertext;
        protected byte[] kyberSecret;

        public BcTlsX25519Kyber(BcTlsX25519KyberDomain domain)
        {
            this.domain = domain;
        }

        public byte[] GenerateEphemeral()
        {
            this.x25519PrivateKey = domain.GenerateX25519PrivateKey();
            this.kyberLocalKeyPair = domain.GetKyberDomain().GenerateKeyPair();

            byte[] x25519Key = domain.GetX25519PublicKey(x25519PrivateKey);
            byte[] kyberKey = domain.GetKyberDomain().EncodePublicKey((KyberPublicKeyParameters)kyberLocalKeyPair.Public);

            return Arrays.Concatenate(x25519Key, kyberKey);
        }

        public void ReceivePeerValue(byte[] peerValue)
        {
            this.x25519PeerPublicKey = Arrays.CopyOf(peerValue, domain.GetX25519PublicKeyByteLength());
            byte[] kyberKey = Arrays.CopyOfRange(peerValue, domain.GetX25519PublicKeyByteLength(), peerValue.Length);

            this.kyberCiphertext = Arrays.Clone(kyberKey);
        }

        public TlsSecret CalculateSecret()
        {
            Debug.WriteLine("calc secret");
            byte[] x25519Secret = domain.CalculateX25519Secret(x25519PrivateKey, x25519PeerPublicKey);

            kyberSecret = domain.GetKyberDomain().DeCap((KyberPrivateKeyParameters)kyberLocalKeyPair.Private, kyberCiphertext);

            return domain.GetKyberDomain().AdoptLocalSecret(Arrays.Concatenate(x25519Secret, kyberSecret));
        }
    }


}
