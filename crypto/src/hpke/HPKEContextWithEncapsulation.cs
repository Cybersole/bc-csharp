using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Hpke
{
    public class HPKEContextWithEncapsulation : HPKEContext
    {
        readonly byte[] encapsulation;
        public HPKEContextWithEncapsulation(HPKEContext context, byte[] encapsulation) : base(context.aead, context.hkdf, context.exporterSecret, context.suiteId)
        {
            this.encapsulation = encapsulation;
        }

        public virtual byte[] GetEncapsulation() => Arrays.Clone(encapsulation);
    }
}