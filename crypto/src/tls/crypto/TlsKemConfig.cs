using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Crypto
{
    public class TlsKEMConfig
    {
        protected readonly int namedGroup;
        protected readonly int kemNamedGroup;

        public TlsKEMConfig(int namedGroup)
        {
            this.namedGroup = namedGroup;
            this.kemNamedGroup = GetKEMNamedGroup(namedGroup);
        }

        public int GetNamedGroup()
        {
            return namedGroup;
        }

        public int GetKEMNamedGroup()
        {
            return kemNamedGroup;
        }

        private int GetKEMNamedGroup(int namedGroup)
        {
            switch (namedGroup)
            {
                case NamedGroup.kyber512:
                //case NamedGroup.secp256Kyber512:
                //case NamedGroup.x25519Kyber512:
                    return NamedGroup.kyber512;
                case NamedGroup.kyber768:
                //case NamedGroup.secp384Kyber768:
                case NamedGroup.x25519Kyber768:
                //case NamedGroup.x448Kyber768:
                    return NamedGroup.kyber768;
                case NamedGroup.kyber1024:
                //case NamedGroup.secp521Kyber1024:
                    return NamedGroup.kyber1024;
                default:
                    return namedGroup;
            }
        }
    }


}
