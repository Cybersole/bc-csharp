using System;
using System.IO;

namespace Org.BouncyCastle.Tls
{
    public sealed class NewSessionTicket13
    {
        public long Lifetime { get; }

        public long AgeAdd { get; }

        public byte[] Nonce { get; }

        public byte[] Label { get; }

        public byte[] Extensions { get; }

        public NewSessionTicket13(long lifetime, long ageAdd, byte[] nonce, byte[] label, byte[] extensions)
        {
            Lifetime = lifetime;
            AgeAdd = ageAdd;
            Nonce = nonce;
            Label = label;
            Extensions = extensions;
        }

        /// <summary>Parse a <see cref="NewSessionTicket"/> from a <see cref="Stream"/>.</summary>
        /// <param name="input">the <see cref="Stream"/> to parse from.</param>
        /// <returns>a <see cref="NewSessionTicket"/> object.</returns>
        /// <exception cref="IOException"/>
        public static NewSessionTicket13 Parse(Stream input)
        {
            var lifetime = TlsUtilities.ReadUint32(input);
            var ageAdd = TlsUtilities.ReadUint32(input);
            var nonce = TlsUtilities.ReadOpaque8(input);
            var label = TlsUtilities.ReadOpaque16(input);
            var extensions = TlsUtilities.ReadOpaque16(input);

            return new(lifetime, ageAdd, nonce, label, extensions);
        }
    }
}
