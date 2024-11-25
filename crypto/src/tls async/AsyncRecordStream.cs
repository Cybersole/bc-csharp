﻿using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Async
{
    /// <summary>An implementation of the TLS 1.0/1.1/1.2 record layer.</summary>
    internal sealed class AsyncRecordStream
    {
        private const int DefaultPlaintextLimit = (1 << 14);

        private readonly Record m_inputRecord = new Record();
        private readonly SequenceNumber m_readSeqNo = new SequenceNumber(), m_writeSeqNo = new SequenceNumber();

        private readonly AsyncTlsProtocol m_handler;
        private readonly Stream m_input;
        private readonly Stream m_output;

        private TlsCipher m_pendingCipher = null;
        private TlsCipher m_readCipher = TlsNullNullCipher.Instance;
        private TlsCipher m_readCipherDeferred = null;
        private TlsCipher m_writeCipher = TlsNullNullCipher.Instance;

        private ProtocolVersion m_writeVersion = null;

        private int m_plaintextLimit = DefaultPlaintextLimit;
        private int m_ciphertextLimit = DefaultPlaintextLimit;
        private bool m_ignoreChangeCipherSpec = false;

        internal AsyncRecordStream(AsyncTlsProtocol handler, Stream input, Stream output)
        {
            this.m_handler = handler;
            this.m_input = input;
            this.m_output = output;
        }

        internal int PlaintextLimit
        {
            get { return m_plaintextLimit; }
        }

        internal void SetPlaintextLimit(int plaintextLimit)
        {
            this.m_plaintextLimit = plaintextLimit;
            this.m_ciphertextLimit = m_readCipher.GetCiphertextDecodeLimit(plaintextLimit);
        }

        internal void SetWriteVersion(ProtocolVersion writeVersion)
        {
            this.m_writeVersion = writeVersion;
        }

        internal void SetIgnoreChangeCipherSpec(bool ignoreChangeCipherSpec)
        {
            this.m_ignoreChangeCipherSpec = ignoreChangeCipherSpec;
        }

        internal void SetPendingCipher(TlsCipher tlsCipher)
        {
            this.m_pendingCipher = tlsCipher;
        }

        /// <exception cref="IOException"/>
        internal void NotifyChangeCipherSpecReceived()
        {
            if (m_pendingCipher == null)
                throw new TlsFatalAlert(AlertDescription.unexpected_message, "No pending cipher");

            EnablePendingCipherRead(false);
        }

        /// <exception cref="IOException"/>
        internal void EnablePendingCipherRead(bool deferred)
        {
            if (m_pendingCipher == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            if (m_readCipherDeferred != null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            if (deferred)
            {
                this.m_readCipherDeferred = m_pendingCipher;
            }
            else
            {
                this.m_readCipher = m_pendingCipher;
                this.m_ciphertextLimit = m_readCipher.GetCiphertextDecodeLimit(m_plaintextLimit);
                m_readSeqNo.Reset();
            }
        }

        /// <exception cref="IOException"/>
        internal void EnablePendingCipherWrite()
        {
            if (m_pendingCipher == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            this.m_writeCipher = this.m_pendingCipher;
            m_writeSeqNo.Reset();
        }

        /// <exception cref="IOException"/>
        internal void FinaliseHandshake()
        {
            if (m_readCipher != m_pendingCipher || m_writeCipher != m_pendingCipher)
                throw new TlsFatalAlert(AlertDescription.handshake_failure);

            this.m_pendingCipher = null;
        }

        internal bool NeedsKeyUpdate()
        {
            return m_writeSeqNo.CurrentValue >= (1L << 20);
        }

        /// <exception cref="IOException"/>
        internal void NotifyKeyUpdateReceived()
        {
            m_readCipher.RekeyDecoder();
            m_readSeqNo.Reset();
        }

        /// <exception cref="IOException"/>
        internal void NotifyKeyUpdateSent()
        {
            m_writeCipher.RekeyEncoder();
            m_writeSeqNo.Reset();
        }

        /// <exception cref="IOException"/>
        internal RecordPreview PreviewRecordHeader(byte[] recordHeader)
        {
            short recordType = CheckRecordType(recordHeader, RecordFormat.TypeOffset);

            //ProtocolVersion recordVersion = TlsUtilities.ReadVersion(recordHeader, RecordFormat.VersionOffset);

            int length = AsyncTlsUtilities.ReadUint16(recordHeader, RecordFormat.LengthOffset);

            CheckLength(length, m_ciphertextLimit, AlertDescription.record_overflow);

            int recordSize = RecordFormat.FragmentOffset + length;
            int applicationDataLimit = 0;

            // NOTE: For TLS 1.3, this only MIGHT be application data
            if (ContentType.application_data == recordType && m_handler.IsApplicationDataReady)
            {
                var cipher = m_readCipher;

                int plaintextDecodeLimit;
                if (cipher is TlsCipherExt tlsCipherExt)
                {
                    plaintextDecodeLimit = tlsCipherExt.GetPlaintextDecodeLimit(length);
                }
                else
                {
                    plaintextDecodeLimit = cipher.GetPlaintextLimit(length);
                }

                applicationDataLimit = System.Math.Max(0, System.Math.Min(m_plaintextLimit, plaintextDecodeLimit));
            }

            return new RecordPreview(recordSize, applicationDataLimit);
        }

        internal RecordPreview PreviewOutputRecord(int contentLength)
        {
            int contentLimit = System.Math.Max(0, System.Math.Min(m_plaintextLimit, contentLength));
            int recordSize = PreviewOutputRecordSize(contentLimit);
            return new RecordPreview(recordSize, contentLimit);
        }

        internal int PreviewOutputRecordSize(int contentLength)
        {
            Debug.Assert(contentLength <= m_plaintextLimit);

            return RecordFormat.FragmentOffset + m_writeCipher.GetCiphertextEncodeLimit(contentLength, m_plaintextLimit);
        }

        /// <exception cref="IOException"/>
        internal async Task<bool> ReadRecordAsync()
        {
            if (!await m_inputRecord.ReadHeaderAsync(m_input))
                return false;

            short recordType = CheckRecordType(m_inputRecord.m_buf, RecordFormat.TypeOffset);

            ProtocolVersion recordVersion = AsyncTlsUtilities.ReadVersion(m_inputRecord.m_buf, RecordFormat.VersionOffset);

            int length = AsyncTlsUtilities.ReadUint16(m_inputRecord.m_buf, RecordFormat.LengthOffset);

            CheckLength(length, m_ciphertextLimit, AlertDescription.record_overflow);

            await m_inputRecord.ReadFragmentAsync(m_input, length);

            TlsDecodeResult decoded;
            try
            {
                if (m_ignoreChangeCipherSpec && ContentType.change_cipher_spec == recordType)
                {
                    CheckChangeCipherSpec(m_inputRecord.m_buf, RecordFormat.FragmentOffset, length);
                    return true;
                }

                decoded = DecodeAndVerify(recordType, recordVersion, m_inputRecord.m_buf, RecordFormat.FragmentOffset,
                    length);
            }
            finally
            {
                m_inputRecord.Reset();
            }

            await m_handler.ProcessRecordAsync(decoded.contentType, decoded.buf, decoded.off, decoded.len);
            return true;
        }

        /// <exception cref="IOException"/>
        internal TlsDecodeResult DecodeAndVerify(short recordType, ProtocolVersion recordVersion, byte[] ciphertext,
            int off, int len)
        {
            long seqNo = m_readSeqNo.NextValue(AlertDescription.unexpected_message);
            TlsDecodeResult decoded = m_readCipher.DecodeCiphertext(seqNo, recordType, recordVersion, ciphertext, off,
                len);

            CheckLength(decoded.len, m_plaintextLimit, AlertDescription.record_overflow);

            /*
             * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
             * or ChangeCipherSpec content types.
             */
            if (decoded.len < 1 && decoded.contentType != ContentType.application_data)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            return decoded;
        }

        /// <exception cref="IOException"/>
        internal Task WriteRecordAsync(short contentType, byte[] plaintext, int plaintextOffset, int plaintextLength)
        {
            return WriteRecordAsync(contentType, plaintext.AsMemory(plaintextOffset, plaintextLength));
        }

        internal async Task WriteRecordAsync(short contentType, ReadOnlyMemory<byte> plaintext)
        {
            // Never send anything until a valid ClientHello has been received
            if (m_writeVersion == null)
                return;

            /*
             * RFC 5246 6.2.1 The length should not exceed 2^14.
             */
            CheckLength(plaintext.Length, m_plaintextLimit, AlertDescription.internal_error);

            /*
             * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
             * or ChangeCipherSpec content types.
             */
            if (plaintext.Length < 1 && contentType != ContentType.application_data)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            long seqNo = m_writeSeqNo.NextValue(AlertDescription.internal_error);
            ProtocolVersion recordVersion = m_writeVersion;

            TlsEncodeResult encoded = m_writeCipher.EncodePlaintext(seqNo, contentType, recordVersion,
                RecordFormat.FragmentOffset, plaintext.Span);

            int ciphertextLength = encoded.len - RecordFormat.FragmentOffset;
            AsyncTlsUtilities.CheckUint16(ciphertextLength);

            AsyncTlsUtilities.WriteUint8(encoded.recordType, encoded.buf, encoded.off + RecordFormat.TypeOffset);
            AsyncTlsUtilities.WriteVersion(recordVersion, encoded.buf, encoded.off + RecordFormat.VersionOffset);
            AsyncTlsUtilities.WriteUint16(ciphertextLength, encoded.buf, encoded.off + RecordFormat.LengthOffset);

            await m_output.WriteAsync(encoded.buf.AsMemory(encoded.off, encoded.len));

            await m_output.FlushAsync();
        }

        /// <exception cref="IOException"/>
        internal void Close()
        {
            m_inputRecord.Reset();

            ExceptionDispatchInfo io = null;
            try
            {
                m_input.Dispose();
            }
            catch (IOException e)
            {
                io = ExceptionDispatchInfo.Capture(e);
            }

            try
            {
                m_output.Dispose();
            }
            catch (IOException e)
            {
                if (io == null)
                {
                    io = ExceptionDispatchInfo.Capture(e);
                }
                else
                {
                    // TODO[tls] Available from JDK 7
                    //io.addSuppressed(e);
                }
            }

            io?.Throw();
        }

        /// <exception cref="IOException"/>
        private void CheckChangeCipherSpec(byte[] buf, int off, int len)
        {
            if (1 != len || (byte)ChangeCipherSpec.change_cipher_spec != buf[off])
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message,
                    "Malformed " + ContentType.GetText(ContentType.change_cipher_spec));
            }
        }

        /// <exception cref="IOException"/>
        private short CheckRecordType(byte[] buf, int off)
        {
            short recordType = AsyncTlsUtilities.ReadUint8(buf, off);

            if (null != m_readCipherDeferred && recordType == ContentType.application_data)
            {
                this.m_readCipher = m_readCipherDeferred;
                this.m_readCipherDeferred = null;
                this.m_ciphertextLimit = m_readCipher.GetCiphertextDecodeLimit(m_plaintextLimit);
                m_readSeqNo.Reset();
            }
            else if (m_readCipher.UsesOpaqueRecordType)
            {
                if (ContentType.application_data != recordType)
                {
                    if (m_ignoreChangeCipherSpec && ContentType.change_cipher_spec == recordType)
                    {
                        // See RFC 8446 D.4.
                    }
                    else
                    {
                        throw new TlsFatalAlert(AlertDescription.unexpected_message,
                            "Opaque " + ContentType.GetText(recordType));
                    }
                }
            }
            else
            {
                switch (recordType)
                {
                case ContentType.application_data:
                {
                    if (!m_handler.IsApplicationDataReady)
                    {
                        throw new TlsFatalAlert(AlertDescription.unexpected_message,
                            "Not ready for " + ContentType.GetText(ContentType.application_data));
                    }
                    break;
                }
                case ContentType.alert:
                case ContentType.change_cipher_spec:
                case ContentType.handshake:
        //        case ContentType.heartbeat:
                    break;
                default:
                    throw new TlsFatalAlert(AlertDescription.unexpected_message,
                        "Unsupported " + ContentType.GetText(recordType));
                }
            }

            return recordType;
        }

        /// <exception cref="IOException"/>
        private static void CheckLength(int length, int limit, short alertDescription)
        {
            if (length > limit)
                throw new TlsFatalAlert(alertDescription);
        }

        private sealed class Record
        {
            private readonly byte[] m_header = new byte[RecordFormat.FragmentOffset];

            internal volatile byte[] m_buf;
            internal volatile int m_pos;

            internal Record()
            {
                this.m_buf = m_header;
                this.m_pos = 0;
            }

            /// <exception cref="IOException"/>
            internal async Task FillToAsync(Stream input, int length)
            {
                while (m_pos < length)
                {
                    int numRead = await input.ReadAsync(m_buf, m_pos, length - m_pos);
                    if (numRead < 1)
                        break;

                    m_pos += numRead;
                }
            }

            /// <exception cref="IOException"/>
            internal async Task ReadFragmentAsync(Stream input, int fragmentLength)
            {
                int recordLength = RecordFormat.FragmentOffset + fragmentLength;
                Resize(recordLength);
                await FillToAsync(input, recordLength);
                if (m_pos < recordLength)
                    throw new EndOfStreamException();
            }

            /// <exception cref="IOException"/>
            internal async Task<bool> ReadHeaderAsync(Stream input)
            {
                await FillToAsync(input, RecordFormat.FragmentOffset);
                if (m_pos == 0)
                    return false;

                if (m_pos < RecordFormat.FragmentOffset)
                    throw new EndOfStreamException();

                return true;
            }

            internal void Reset()
            {
                m_buf = m_header;
                m_pos = 0;
            }

            private void Resize(int length)
            {
                if (m_buf.Length < length)
                {
                    byte[] tmp = new byte[length];
                    Array.Copy(m_buf, 0, tmp, 0, m_pos);
                    m_buf = tmp;
                }
            }
        }

        private sealed class SequenceNumber
        {
            private long m_value = 0L;
            private bool m_exhausted = false;

            internal long CurrentValue
            {
                get { lock (this) return m_value; }
            }

            /// <exception cref="TlsFatalAlert"/>
            internal long NextValue(short alertDescription)
            {
                lock (this)
                {
                    if (m_exhausted)
                        throw new TlsFatalAlert(alertDescription, "Sequence numbers exhausted");

                    long result = m_value;
                    if (++m_value == 0L)
                    {
                        this.m_exhausted = true;
                    }
                    return result;
                }
            }

            internal void Reset()
            {
                lock (this)
                {
                    this.m_value = 0L;
                    this.m_exhausted = false;
                }
            }
        }
    }
}
