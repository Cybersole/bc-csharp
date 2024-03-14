using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using System;

namespace Org.BouncyCastle.Crypto.Agreement
{
    public class XDHBasicAgreement : IBasicAgreement
    {
        private AsymmetricKeyParameter key;
        private IRawAgreement agreement;
        private int fieldSize = 0;
        public XDHBasicAgreement()
        {
        }

        public virtual void Init(ICipherParameters key)
        {
            if (key is X25519PrivateKeyParameters)
            {
                this.fieldSize = 32;
                this.agreement = new X25519Agreement();
            }
            else if (key is X448PrivateKeyParameters)
            {
                this.fieldSize = 56;
                this.agreement = new X448Agreement();
            }
            else
            {
                throw new ArgumentException("key is neither X25519 nor X448");
            }

            this.key = (AsymmetricKeyParameter)key;
            agreement.Init(key);
        }

        public virtual int GetFieldSize()
        {
            return fieldSize;
        }

        public virtual BigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            byte[] Z = new byte[fieldSize];
            agreement.CalculateAgreement(pubKey, Z, 0);
            return new BigInteger(1, Z);
        }
    }
}