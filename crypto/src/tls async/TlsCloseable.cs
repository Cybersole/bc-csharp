using System;
using System.IO;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Async
{
    public interface TlsCloseable
    {
        /// <exception cref="IOException"/>
        Task CloseAsync();
    }
}
