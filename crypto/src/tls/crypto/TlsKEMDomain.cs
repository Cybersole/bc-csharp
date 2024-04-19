using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Crypto
{
    public interface TlsKEMDomain
    {
        TlsAgreement CreateKEM();
    }
}
