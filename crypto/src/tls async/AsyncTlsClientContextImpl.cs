using System;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls.Async
{
    internal class AsyncTlsClientContextImpl
        : AbstractTlsContext, TlsClientContext
    {
        internal AsyncTlsClientContextImpl(TlsCrypto crypto)
            : base(crypto, ConnectionEnd.client)
        {
        }

        public override bool IsServer
        {
            get { return false; }
        }
    }
}
