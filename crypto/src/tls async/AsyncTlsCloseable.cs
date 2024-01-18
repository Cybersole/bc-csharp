using System;
using System.IO;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Tls.Async
{
    public interface AsyncTlsCloseable
    {
        /// <exception cref="IOException"/>
        Task CloseAsync();
    }
}
