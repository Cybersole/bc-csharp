using System;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    public interface TlsPsk
    {
        byte[] Identity { get; }

        long ObfuscatedTicketAge { get; set; }

        TlsSecret Key { get; }

        int PrfAlgorithm { get; }
    }
}
