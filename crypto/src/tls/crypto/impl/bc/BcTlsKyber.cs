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
    public class BcTlsKyber : TlsAgreement
    {
        protected readonly BcTlsKyberDomain domain;

        protected AsymmetricCipherKeyPair localKeyPair;
        protected KyberPublicKeyParameters peerPublicKey;
        protected byte[] ciphertext;
        protected byte[] secret;

        public BcTlsKyber(BcTlsKyberDomain domain)
        {
            this.domain = domain;
        }

        public byte[] GenerateEphemeral()
        {
            this.localKeyPair = domain.GenerateKeyPair();

            return domain.EncodePublicKey((KyberPublicKeyParameters)localKeyPair.Public);
        }

        public void ReceivePeerValue(byte[] peerValue)
        {
            this.ciphertext = Arrays.Clone(peerValue);
        }

        public TlsSecret CalculateSecret()
        {
            return domain.AdoptLocalSecret(domain.DeCap((KyberPrivateKeyParameters)localKeyPair.Private, ciphertext));
        }
    }
}
