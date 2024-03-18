using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Async
{
    public abstract class AsyncTlsProtocol
        : AsyncTlsCloseable
    {
        /*
         * Connection States.
         * 
         * NOTE: Redirection of handshake messages to TLS 1.3 handlers assumes CS_START, CS_CLIENT_HELLO
         * are lower than any of the other values.
         */
        protected const short CS_START = 0;
        protected const short CS_CLIENT_HELLO = 1;
        protected const short CS_SERVER_HELLO_RETRY_REQUEST = 2;
        protected const short CS_CLIENT_HELLO_RETRY = 3;
        protected const short CS_SERVER_HELLO = 4;
        protected const short CS_SERVER_ENCRYPTED_EXTENSIONS = 5;
        protected const short CS_SERVER_SUPPLEMENTAL_DATA = 6;
        protected const short CS_SERVER_CERTIFICATE = 7;
        protected const short CS_SERVER_CERTIFICATE_STATUS = 8;
        protected const short CS_SERVER_CERTIFICATE_VERIFY = 9;
        protected const short CS_SERVER_KEY_EXCHANGE = 10;
        protected const short CS_SERVER_CERTIFICATE_REQUEST = 11;
        protected const short CS_SERVER_HELLO_DONE = 12;
        protected const short CS_CLIENT_END_OF_EARLY_DATA = 13;
        protected const short CS_CLIENT_SUPPLEMENTAL_DATA = 14;
        protected const short CS_CLIENT_CERTIFICATE = 15;
        protected const short CS_CLIENT_KEY_EXCHANGE = 16;
        protected const short CS_CLIENT_CERTIFICATE_VERIFY = 17;
        protected const short CS_CLIENT_FINISHED = 18;
        protected const short CS_SERVER_SESSION_TICKET = 19;
        protected const short CS_SERVER_FINISHED = 20;
        protected const short CS_END = 21;

        protected bool IsLegacyConnectionState()
        {
            switch (m_connectionState)
            {
            case CS_START:
            case CS_CLIENT_HELLO:
            case CS_SERVER_HELLO:
            case CS_SERVER_SUPPLEMENTAL_DATA:
            case CS_SERVER_CERTIFICATE:
            case CS_SERVER_CERTIFICATE_STATUS:
            case CS_SERVER_KEY_EXCHANGE:
            case CS_SERVER_CERTIFICATE_REQUEST:
            case CS_SERVER_HELLO_DONE:
            case CS_CLIENT_SUPPLEMENTAL_DATA:
            case CS_CLIENT_CERTIFICATE:
            case CS_CLIENT_KEY_EXCHANGE:
            case CS_CLIENT_CERTIFICATE_VERIFY:
            case CS_CLIENT_FINISHED:
            case CS_SERVER_SESSION_TICKET:
            case CS_SERVER_FINISHED:
            case CS_END:
                return true;

            case CS_SERVER_HELLO_RETRY_REQUEST:
            case CS_CLIENT_HELLO_RETRY:
            case CS_SERVER_ENCRYPTED_EXTENSIONS:
            case CS_SERVER_CERTIFICATE_VERIFY:
            case CS_CLIENT_END_OF_EARLY_DATA:
            default:
                return false;
            }
        }

        protected bool IsTlsV13ConnectionState()
        {
            switch (m_connectionState)
            {
            case CS_START:
            case CS_CLIENT_HELLO:
            case CS_SERVER_HELLO_RETRY_REQUEST:
            case CS_CLIENT_HELLO_RETRY:
            case CS_SERVER_HELLO:
            case CS_SERVER_ENCRYPTED_EXTENSIONS:
            case CS_SERVER_CERTIFICATE_REQUEST:
            case CS_SERVER_CERTIFICATE:
            case CS_SERVER_CERTIFICATE_VERIFY:
            case CS_SERVER_FINISHED:
            case CS_CLIENT_END_OF_EARLY_DATA:
            case CS_CLIENT_CERTIFICATE:
            case CS_CLIENT_CERTIFICATE_VERIFY:
            case CS_CLIENT_FINISHED:
            case CS_END:
                return true;

            case CS_SERVER_SUPPLEMENTAL_DATA:
            case CS_SERVER_CERTIFICATE_STATUS:
            case CS_SERVER_KEY_EXCHANGE:
            case CS_SERVER_HELLO_DONE:
            case CS_CLIENT_SUPPLEMENTAL_DATA:
            case CS_CLIENT_KEY_EXCHANGE:
            case CS_SERVER_SESSION_TICKET:
            default:
                return false;
            }
        }

        /*
         * Different modes to handle the known IV weakness
         */
        protected const short ADS_MODE_1_Nsub1 = 0; // 1/n-1 record splitting
        protected const short ADS_MODE_0_N = 1; // 0/n record splitting
        protected const short ADS_MODE_0_N_FIRSTONLY = 2; // 0/n record splitting on first data fragment only

        /*
         * Queues for data from some protocols.
         */
        private readonly ByteQueue m_applicationDataQueue = new ByteQueue(0);
        private readonly ByteQueue m_alertQueue = new ByteQueue(2);
        private readonly ByteQueue m_handshakeQueue = new ByteQueue(0);
        //private readonly ByteQueue m_heartbeatQueue = new ByteQueue(0);

        internal readonly AsyncRecordStream m_recordStream;
        internal readonly object m_recordWriteLock = new object();

        private int m_maxHandshakeMessageSize = -1;

        internal TlsHandshakeHash m_handshakeHash;

        private AsyncTlsStream m_tlsStream = null;

        private SemaphoreSlim _semaphore = new(1);

        private volatile bool m_closed = false;
        private volatile bool m_failedWithError = false;
        private volatile bool m_appDataReady = false;
        private volatile bool m_appDataSplitEnabled = true;
        private volatile bool m_keyUpdateEnabled = false;
        //private volatile bool m_keyUpdatePendingReceive = false;
        private volatile bool m_keyUpdatePendingSend = false;
        private volatile bool m_resumableHandshake = false;
        private volatile int m_appDataSplitMode = ADS_MODE_1_Nsub1;

        protected TlsSession m_tlsSession = null;
        protected SessionParameters m_sessionParameters = null;
        protected TlsSecret m_sessionMasterSecret = null;

        protected byte[] m_retryCookie = null;
        protected int m_retryGroup = -1;
        protected IDictionary<int, byte[]> m_clientExtensions = null;
        protected IDictionary<int, byte[]> m_serverExtensions = null;

        protected short m_connectionState = CS_START;
        protected bool m_selectedPsk13 = false;
        protected bool m_receivedChangeCipherSpec = false;
        protected bool m_expectSessionTicket = false;

        public AsyncTlsProtocol(Stream stream)
        {       
            this.m_recordStream = new AsyncRecordStream(this, stream, stream);
        }

        /// <exception cref="IOException"/>
        public virtual async Task ResumeHandshakeAsync()
        {
            if (!IsHandshaking)
                throw new InvalidOperationException("No handshake in progress");

            await BlockForHandshakeAsync();
        }

        /// <exception cref="IOException"/>
        protected virtual void CloseConnection()
        {
            m_recordStream.Close();
        }

        protected abstract TlsContext Context { get; }

        internal abstract AbstractTlsContext ContextAdmin { get; }

        protected abstract AsyncTlsPeer Peer { get; }

        /// <exception cref="IOException"/>
        protected virtual async Task HandleAlertMessageAsync(short alertLevel, short alertDescription)
        {
            Peer.NotifyAlertReceived(alertLevel, alertDescription);

            if (alertLevel == AlertLevel.warning)
            {
                await HandleAlertWarningMessageAsync(alertDescription);
            }
            else
            {
                HandleFailure();

                throw new TlsFatalAlertReceived(alertDescription);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual async Task HandleAlertWarningMessageAsync(short alertDescription)
        {
            switch (alertDescription)
            {
            /*
             * RFC 5246 7.2.1. The other party MUST respond with a close_notify alert of its own
             * and close down the connection immediately, discarding any pending writes.
             */
            case AlertDescription.close_notify:
            {
                if (!m_appDataReady)
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);

                await HandleCloseAsync(false);
                break;
            }
            case AlertDescription.no_certificate:
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            case AlertDescription.no_renegotiation:
            {
                // TODO[reneg] Give peer the option to tolerate this
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void HandleChangeCipherSpecMessage()
        {
        }

        /// <exception cref="IOException"/>
        protected virtual async Task HandleCloseAsync(bool user_canceled)
        {
            if (!m_closed)
            {
                this.m_closed = true;

                if (!m_appDataReady)
                {
                    CleanupHandshake();

                    if (user_canceled)
                    {
                        await RaiseAlertWarningAsync(AlertDescription.user_canceled, "User canceled handshake");
                    }
                }

                await RaiseAlertWarningAsync(AlertDescription.close_notify, "Connection closed");

                CloseConnection();

                AsyncTlsUtilities.NotifyConnectionClosed(Peer);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual async Task HandleExceptionAsync(short alertDescription, string message, Exception e)
        {
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //if ((m_appDataReady || IsResumableHandshake()) && (e is InterruptedIOException))
            //    return;

            if (!m_closed)
            {
                await RaiseAlertFatalAsync(alertDescription, message, e);

                HandleFailure();
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void HandleFailure()
        {
            this.m_closed = true;
            this.m_failedWithError = true;

            /*
             * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
             * without proper close_notify messages with level equal to warning.
             */
            // TODO This isn't quite in the right place. Also, as of TLS 1.1 the above is obsolete.
            InvalidateSession();

            if (!m_appDataReady)
            {
                CleanupHandshake();
            }

            CloseConnection();

            AsyncTlsUtilities.NotifyConnectionClosed(Peer);
        }

        /// <exception cref="IOException"/>
        protected abstract Task HandleHandshakeMessageAsync(short type, HandshakeMessageInput buf);

        /// <exception cref="IOException"/>
        protected virtual void ApplyMaxFragmentLengthExtension(short maxFragmentLength)
        {
            if (maxFragmentLength >= 0)
            {
                if (!MaxFragmentLength.IsValid(maxFragmentLength))
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                int plainTextLimit = 1 << (8 + maxFragmentLength);
                m_recordStream.SetPlaintextLimit(plainTextLimit);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void CheckReceivedChangeCipherSpec(bool expected)
        {
            if (expected != m_receivedChangeCipherSpec)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        /// <exception cref="IOException"/>
        protected virtual async Task BlockForHandshakeAsync()
        {
            while (m_connectionState != CS_END)
            {
                if (IsClosed)
                {
                    // NOTE: Any close during the handshake should have raised an exception.
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                await SafeReadRecordAsync();
            }
        }

        /// <exception cref="IOException"/>
        protected virtual Task BeginHandshakeAsync()
        {
            AbstractTlsContext context = ContextAdmin;
            AsyncTlsPeer peer = Peer;

            this.m_maxHandshakeMessageSize = System.Math.Max(1024, peer.GetMaxHandshakeMessageSize());

            this.m_handshakeHash = new DeferredHash(context);
            this.m_connectionState = CS_START;
            this.m_selectedPsk13 = false;

            context.HandshakeBeginning(peer);

            SecurityParameters securityParameters = context.SecurityParameters;

            securityParameters.m_extendedPadding = peer.ShouldUseExtendedPadding();

            return Task.CompletedTask;
        }

        protected virtual void CleanupHandshake()
        {
            TlsContext context = Context;
            if (null != context)
            {
                SecurityParameters securityParameters = context.SecurityParameters;
                if (null != securityParameters)
                {
                    securityParameters.Clear();
                }
            }

            this.m_tlsSession = null;
            this.m_sessionParameters = null;
            this.m_sessionMasterSecret = null;

            this.m_retryCookie = null;
            this.m_retryGroup = -1;
            this.m_clientExtensions = null;
            this.m_serverExtensions = null;

            this.m_selectedPsk13 = false;
            this.m_receivedChangeCipherSpec = false;
            this.m_expectSessionTicket = false;
        }

        /// <exception cref="IOException"/>
        protected virtual void CompleteHandshake()
        {
            try
            {
                AbstractTlsContext context = ContextAdmin;
                SecurityParameters securityParameters = context.SecurityParameters;

                if (!context.IsHandshaking ||
                    null == securityParameters.LocalVerifyData ||
                    null == securityParameters.PeerVerifyData)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                m_recordStream.FinaliseHandshake();
                this.m_connectionState = CS_END;

                // TODO Prefer to set to null, but would need guards elsewhere
                this.m_handshakeHash = new DeferredHash(context);

                m_alertQueue.Shrink();
                m_handshakeQueue.Shrink();

                ProtocolVersion negotiatedVersion = securityParameters.NegotiatedVersion;

                this.m_appDataSplitEnabled = !AsyncTlsUtilities.IsTlsV11(negotiatedVersion);
                this.m_appDataReady = true;

                this.m_keyUpdateEnabled = AsyncTlsUtilities.IsTlsV13(negotiatedVersion);

                this.m_tlsStream = new AsyncTlsStream(this);

                if (m_sessionParameters == null)
                {
                    this.m_sessionMasterSecret = securityParameters.MasterSecret;

                    this.m_sessionParameters = new SessionParameters.Builder()
                        .SetCipherSuite(securityParameters.CipherSuite)
                        .SetExtendedMasterSecret(securityParameters.IsExtendedMasterSecret)
                        .SetLocalCertificate(securityParameters.LocalCertificate)
                        .SetMasterSecret(context.Crypto.AdoptSecret(m_sessionMasterSecret))
                        .SetNegotiatedVersion(securityParameters.NegotiatedVersion)
                        .SetPeerCertificate(securityParameters.PeerCertificate)
                        .SetPskIdentity(securityParameters.PskIdentity)
                        .SetSrpIdentity(securityParameters.SrpIdentity)
                        // TODO Consider filtering extensions that aren't relevant to resumed sessions
                        .SetServerExtensions(m_serverExtensions)
                        .Build();

                    this.m_tlsSession = AsyncTlsUtilities.ImportSession(securityParameters.SessionID, m_sessionParameters);
                }
                else
                {
                    securityParameters.m_localCertificate = m_sessionParameters.LocalCertificate;
                    securityParameters.m_peerCertificate = m_sessionParameters.PeerCertificate;
                    securityParameters.m_pskIdentity = m_sessionParameters.PskIdentity;
                    securityParameters.m_srpIdentity = m_sessionParameters.SrpIdentity;
                }

                context.HandshakeComplete(Peer, m_tlsSession);
            }
            finally
            {
                CleanupHandshake();
            }
        }

        /// <exception cref="IOException"/>
        internal async Task ProcessRecordAsync(short protocol, byte[] buf, int off, int len)
        {
            /*
             * Have a look at the protocol type, and add it to the correct queue.
             */
            switch (protocol)
            {
            case ContentType.alert:
            {
                m_alertQueue.AddData(buf, off, len);
                await ProcessAlertQueueAsync();
                break;
            }
            case ContentType.application_data:
            {
                if (!m_appDataReady)
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);

                m_applicationDataQueue.AddData(buf, off, len);
                ProcessApplicationDataQueue();
                break;
            }
            case ContentType.change_cipher_spec:
            {
                ProcessChangeCipherSpec(buf, off, len);
                break;
            }
            case ContentType.handshake:
            {
                if (m_handshakeQueue.Available > 0)
                {
                    m_handshakeQueue.AddData(buf, off, len);
                    await ProcessHandshakeQueueAsync(m_handshakeQueue);
                }
                else
                {
                    ByteQueue tmpQueue = new ByteQueue(buf, off, len);
                    await ProcessHandshakeQueueAsync(tmpQueue);
                    int remaining = tmpQueue.Available;
                    if (remaining > 0)
                    {
                        m_handshakeQueue.AddData(buf, off + len - remaining, remaining);
                    }
                }
                break;
            }
            //case ContentType.heartbeat:
            //{
            //    if (!m_appDataReady)
            //        throw new TlsFatalAlert(AlertDescription.unexpected_message);

            //    // TODO[RFC 6520]
            //    m_heartbeatQueue.addData(buf, off, len);
            //    ProcessHeartbeatQueue();
            //    break;
            //}
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        /// <exception cref="IOException"/>
        private async Task ProcessHandshakeQueueAsync(ByteQueue queue)
        {
            /*
             * We need the first 4 bytes, they contain type and length of the message.
             */
            while (queue.Available >= 4)
            {
                int header = queue.ReadInt32();

                short type = (short)((uint)header >> 24);
                if (!HandshakeType.IsRecognized(type))
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message,
                        "Handshake message of unrecognized type: " + type);
                }

                int length = header & 0x00FFFFFF;
                if (length > m_maxHandshakeMessageSize)
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error,
                        "Handshake message length exceeds the maximum: " + HandshakeType.GetText(type) + ", " + length
                            + " > " + m_maxHandshakeMessageSize);
                }

                int totalLength = 4 + length;
                if (queue.Available < totalLength)
                {
                    // Not enough bytes in the buffer to read the full message.
                    break;
                }

                /*
                 * Check ChangeCipherSpec status
                 */
                switch (type)
                {
                case HandshakeType.hello_request:
                    break;

                default:
                {
                    ProtocolVersion negotiatedVersion = Context.ServerVersion;
                    if (null != negotiatedVersion && AsyncTlsUtilities.IsTlsV13(negotiatedVersion))
                        break;

                    CheckReceivedChangeCipherSpec(HandshakeType.finished == type);
                    break;
                }
                }

                HandshakeMessageInput buf = queue.ReadHandshakeMessage(totalLength);

                switch (type)
                {
                /*
                 * These message types aren't included in the transcript.
                 */
                case HandshakeType.hello_request:
                case HandshakeType.key_update:
                    break;

                /*
                 * Not included in the transcript for (D)TLS 1.3+
                 */
                case HandshakeType.new_session_ticket:
                {
                    ProtocolVersion negotiatedVersion = Context.ServerVersion;
                    if (null != negotiatedVersion && !AsyncTlsUtilities.IsTlsV13(negotiatedVersion))
                    {
                        buf.UpdateHash(m_handshakeHash);
                    }

                    break;
                }

                /*
                 * These message types are deferred to the handler to explicitly update the transcript.
                 */
                case HandshakeType.certificate_verify:
                case HandshakeType.client_hello:
                case HandshakeType.finished:
                case HandshakeType.server_hello:
                    break;

                /*
                 * For all others we automatically update the transcript immediately. 
                 */
                default:
                {
                    buf.UpdateHash(m_handshakeHash);
                    break;
                }
                }

                buf.Seek(4L, SeekOrigin.Current);

                await HandleHandshakeMessageAsync(type, buf);
            }
        }

        private void ProcessApplicationDataQueue()
        {
            /*
             * There is nothing we need to do here.
             * 
             * This function could be used for callbacks when application data arrives in the future.
             */
        }

        /// <exception cref="IOException"/>
        private async Task ProcessAlertQueueAsync()
        {
            while (m_alertQueue.Available >= 2)
            {
                /*
                 * An alert is always 2 bytes. Read the alert.
                 */
                byte[] alert = m_alertQueue.RemoveData(2, 0);
                short alertLevel = alert[0];
                short alertDescription = alert[1];

                await HandleAlertMessageAsync(alertLevel, alertDescription);
            }
        }

        /// <summary>This method is called, when a change cipher spec message is received.</summary>
        /// <exception cref="IOException">If the message has an invalid content or the handshake is not in the correct
        /// state.</exception>
        private void ProcessChangeCipherSpec(byte[] buf, int off, int len)
        {
            ProtocolVersion negotiatedVersion = Context.ServerVersion;
            if (null == negotiatedVersion || AsyncTlsUtilities.IsTlsV13(negotiatedVersion))
            {
                // See RFC 8446 D.4.
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            for (int i = 0; i < len; ++i)
            {
                short message = AsyncTlsUtilities.ReadUint8(buf, off + i);

                if (message != ChangeCipherSpec.change_cipher_spec)
                    throw new TlsFatalAlert(AlertDescription.decode_error);

                if (this.m_receivedChangeCipherSpec
                    || m_alertQueue.Available > 0
                    || m_handshakeQueue.Available > 0)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                m_recordStream.NotifyChangeCipherSpecReceived();

                this.m_receivedChangeCipherSpec = true;

                HandleChangeCipherSpecMessage();
            }
        }

        public virtual int ApplicationDataAvailable
        {
            get { return m_applicationDataQueue.Available; }
        }

        /// <summary>Read data from the network.</summary>
        /// <remarks>
        /// The method will return immediately, if there is still some data left in the buffer, or block until some
        /// application data has been read from the network.
        /// </remarks>
        /// <param name="buffer">The buffer where the data will be copied to.</param>
        /// <param name="offset">The position where the data will be placed in the buffer.</param>
        /// <param name="count">The maximum number of bytes to read.</param>
        /// <returns>The number of bytes read.</returns>
        /// <exception cref="IOException">If something goes wrong during reading data.</exception>
        public virtual Task<int> ReadApplicationDataAsync(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            return ReadApplicationDataAsync(buffer.AsMemory(offset, count));
        }

        public virtual async Task<int> ReadApplicationDataAsync(Memory<byte> buffer)
        {
            if (!m_appDataReady)
                throw new InvalidOperationException("Cannot read application data until initial handshake completed.");

            while (m_applicationDataQueue.Available < 1)
            {
                if (this.m_closed)
                {
                    if (this.m_failedWithError)
                        throw new IOException("Cannot read application data on failed TLS connection");

                    return 0;
                }

                /*
                 * NOTE: Only called more than once when empty records are received, so no special
                 * InterruptedIOException handling is necessary.
                 */
                await SafeReadRecordAsync();
            }

            int count = buffer.Length;
            if (count > 0)
            {
                count = System.Math.Min(count, m_applicationDataQueue.Available);
                m_applicationDataQueue.RemoveData(buffer.Span[..count], 0);
            }
            return count;
        }

        /// <exception cref="IOException"/>
        protected virtual async Task<RecordPreview> SafePreviewRecordHeaderAsync(byte[] recordHeader)
        {
            try
            {
                return m_recordStream.PreviewRecordHeader(recordHeader);
            }
            catch (TlsFatalAlert e)
            {
                await HandleExceptionAsync(e.AlertDescription, "Failed to read record", e);
                throw;
            }
            catch (IOException e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to read record", e);
                throw;
            }
            catch (Exception e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to read record", e);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual async Task SafeReadRecordAsync()
        {
            try
            {
                if (await m_recordStream.ReadRecordAsync())
                    return;

                if (!m_appDataReady)
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);

                if (!Peer.RequiresCloseNotify())
                {
                    await HandleCloseAsync(false);
                    return;
                }
            }
            catch (TlsFatalAlertReceived)
            {
                // Connection failure already handled at source
                throw;
            }
            catch (TlsFatalAlert e)
            {
                await HandleExceptionAsync(e.AlertDescription, "Failed to read record", e);
                throw;
            }
            catch (IOException e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to read record", e);
                throw;
            }
            catch (Exception e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to read record", e);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }

            HandleFailure();

            throw new TlsNoCloseNotifyException();
        }

        protected virtual async Task SafeWriteRecordAsync(short type, ReadOnlyMemory<byte> buffer)
        {
            try
            {
                await m_recordStream.WriteRecordAsync(type, buffer);
            }
            catch (TlsFatalAlert e)
            {
                await HandleExceptionAsync(e.AlertDescription, "Failed to write record", e);
                throw;
            }
            catch (IOException e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to write record", e);
                throw;
            }
            catch (Exception e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to write record", e);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual async Task SafeWriteRecordAsync(short type, byte[] buf, int offset, int len)
        {
            try
            {
                await m_recordStream.WriteRecordAsync(type, buf, offset, len);
            }
            catch (TlsFatalAlert e)
            {
                await HandleExceptionAsync(e.AlertDescription, "Failed to write record", e);
                throw;
            }
            catch (IOException e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to write record", e);
                throw;
            }
            catch (Exception e)
            {
                await HandleExceptionAsync(AlertDescription.internal_error, "Failed to write record", e);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        /// <summary>Write some application data.</summary>
        /// <remarks>
        /// Fragmentation is handled internally. Usable in both blocking/non-blocking modes.<br/><br/>
        /// In blocking mode, the output will be automatically sent via the underlying transport. In non-blocking mode,
        /// call <see cref="ReadOutput(byte[], int, int)"/> to get the output bytes to send to the peer.<br/><br/>
        /// This method must not be called until after the initial handshake is complete. Attempting to call it earlier
        /// will result in an <see cref="InvalidOperationException"/>.
        /// </remarks>
        /// <param name="buffer">The buffer containing application data to send.</param>
        /// <param name="offset">The offset at which the application data begins</param>
        /// <param name="count">The number of bytes of application data.</param>
        /// <exception cref="InvalidOperationException">If called before the initial handshake has completed.
        /// </exception>
        /// <exception cref="IOException">If connection is already closed, or for encryption or transport errors.
        /// </exception>
        public virtual Task WriteApplicationDataAsync(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            return WriteApplicationDataAsync(buffer.AsMemory(offset, count));
        }

        public virtual async Task WriteApplicationDataAsync(ReadOnlyMemory<byte> buffer)
        {
            if (!m_appDataReady)
                throw new InvalidOperationException(
                    "Cannot write application data until initial handshake completed.");

            await _semaphore.WaitAsync();

            try
            {
                while (!buffer.IsEmpty)
                {
                    if (m_closed)
                        throw new IOException("Cannot write application data on closed/failed TLS connection");

                    /*
                     * RFC 5246 6.2.1. Zero-length fragments of Application data MAY be sent as they are
                     * potentially useful as a traffic analysis countermeasure.
                     * 
                     * NOTE: Actually, implementations appear to have settled on 1/n-1 record splitting.
                     */
                    if (m_appDataSplitEnabled)
                    {
                        /*
                         * Protect against known IV attack!
                         * 
                         * DO NOT REMOVE THIS CODE, EXCEPT YOU KNOW EXACTLY WHAT YOU ARE DOING HERE.
                         */
                        switch (m_appDataSplitMode)
                        {
                            case ADS_MODE_0_N_FIRSTONLY:
                                {
                                    this.m_appDataSplitEnabled = false;
                                    await SafeWriteRecordAsync(ContentType.application_data, AsyncTlsUtilities.EmptyBytes, 0, 0);
                                    break;
                                }
                            case ADS_MODE_0_N:
                                {
                                    await SafeWriteRecordAsync(ContentType.application_data, AsyncTlsUtilities.EmptyBytes, 0, 0);
                                    break;
                                }
                            case ADS_MODE_1_Nsub1:
                            default:
                                {
                                    if (buffer.Length > 1)
                                    {
                                        await SafeWriteRecordAsync(ContentType.application_data, buffer[..1]);
                                        buffer = buffer[1..];
                                    }
                                    break;
                                }
                        }
                    }
                    else if (m_keyUpdateEnabled)
                    {
                        if (m_keyUpdatePendingSend)
                        {
                            await Send13KeyUpdateAsync(false);
                        }
                        else if (m_recordStream.NeedsKeyUpdate())
                        {
                            await Send13KeyUpdateAsync(true);
                        }
                    }

                    // Fragment data according to the current fragment limit.
                    int toWrite = System.Math.Min(buffer.Length, m_recordStream.PlaintextLimit);
                    await SafeWriteRecordAsync(ContentType.application_data, buffer[..toWrite]);
                    buffer = buffer[toWrite..];
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public virtual int AppDataSplitMode
        {
            get { return m_appDataSplitMode; }
            set
            {
                if (value < ADS_MODE_1_Nsub1 || value > ADS_MODE_0_N_FIRSTONLY)
                    throw new InvalidOperationException("Illegal appDataSplitMode mode: " + value);

                this.m_appDataSplitMode = value;
            }
        }

        public virtual bool IsResumableHandshake
        {
            get { return m_resumableHandshake; }
            set { this.m_resumableHandshake = value; }
        }

        /// <exception cref="IOException"/>
        internal async Task WriteHandshakeMessageAsync(byte[] buf, int off, int len)
        {
            if (len < 4)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            short type = AsyncTlsUtilities.ReadUint8(buf, off);
            switch (type)
            {
            /*
             * These message types aren't included in the transcript.
             */
            case HandshakeType.hello_request:
            case HandshakeType.key_update:
                break;

            /*
             * Not included in the transcript for (D)TLS 1.3+
             */
            case HandshakeType.new_session_ticket:
            {
                ProtocolVersion negotiatedVersion = Context.ServerVersion;
                if (null != negotiatedVersion && !AsyncTlsUtilities.IsTlsV13(negotiatedVersion))
                {
                    m_handshakeHash.Update(buf, off, len);
                }

                break;
            }

            /*
             * These message types are deferred to the writer to explicitly update the transcript.
             */
            case HandshakeType.client_hello:
                break;

            /*
             * For all others we automatically update the transcript. 
             */
            default:
            {
                m_handshakeHash.Update(buf, off, len);
                break;
            }
            }

            int total = 0;
            do
            {
                // Fragment data according to the current fragment limit.
                int toWrite = System.Math.Min(len - total, m_recordStream.PlaintextLimit);
                await SafeWriteRecordAsync(ContentType.handshake, buf, off + total, toWrite);
                total += toWrite;
            }
            while (total < len);
        }

        /// <summary>The secure bidirectional stream for this connection</summary>
        /// <remarks>Only allowed in blocking mode.</remarks>
        public virtual Stream Stream => m_tlsStream;

        public virtual int ApplicationDataLimit
        {
            get { return m_recordStream.PlaintextLimit; }
        }

        protected virtual bool EstablishSession(TlsSession sessionToResume)
        {
            this.m_tlsSession = null;
            this.m_sessionParameters = null;
            this.m_sessionMasterSecret = null;

            if (null == sessionToResume || !sessionToResume.IsResumable)
                return false;

            SessionParameters sessionParameters = sessionToResume.ExportSessionParameters();
            if (null == sessionParameters)
                return false;

            ProtocolVersion sessionVersion = sessionParameters.NegotiatedVersion;
            if (null == sessionVersion || !sessionVersion.IsTls)
                return false;

            bool isEms = sessionParameters.IsExtendedMasterSecret;
            if (sessionVersion.IsSsl)
            {
                if (isEms)
                    return false;
            }
            else if (!AsyncTlsUtilities.IsExtendedMasterSecretOptional(sessionVersion))
            {
                if (!isEms)
                    return false;
            }

            TlsCrypto crypto = Context.Crypto;
            TlsSecret sessionMasterSecret = AsyncTlsUtilities.GetSessionMasterSecret(crypto, sessionParameters.MasterSecret);
            if (null == sessionMasterSecret)
                return false;

            this.m_tlsSession = sessionToResume;
            this.m_sessionParameters = sessionParameters;
            this.m_sessionMasterSecret = sessionMasterSecret;

            return true;
        }

        protected virtual void CancelSession()
        {
            if (m_sessionMasterSecret != null)
            {
                m_sessionMasterSecret.Destroy();
                this.m_sessionMasterSecret = null;
            }

            if (m_sessionParameters != null)
            {
                m_sessionParameters.Clear();
                this.m_sessionParameters = null;
            }

            this.m_tlsSession = null;
        }

        protected virtual void InvalidateSession()
        {
            if (m_tlsSession != null)
            {
                m_tlsSession.Invalidate();
            }

            CancelSession();
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessFinishedMessage(MemoryStream buf)
        {
            TlsContext context = Context;
            SecurityParameters securityParameters = context.SecurityParameters;
            bool isServerContext = context.IsServer;

            Span<byte> verify_data = stackalloc byte[securityParameters.VerifyDataLength];
            AsyncTlsUtilities.ReadFully(verify_data, buf);

            AssertEmpty(buf);

            byte[] expected_verify_data = AsyncTlsUtilities.CalculateVerifyData(context, m_handshakeHash, !isServerContext);

            /*
             * Compare both checksums.
             */
            if (!Arrays.FixedTimeEquals(expected_verify_data, verify_data))
            {
                /*
                 * Wrong checksum in the finished message.
                 */
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }

            securityParameters.m_peerVerifyData = expected_verify_data;

            if (!securityParameters.IsResumedSession || securityParameters.IsExtendedMasterSecret)
            {
                if (null == securityParameters.LocalVerifyData)
                {
                    securityParameters.m_tlsUnique = expected_verify_data;
                }
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void Process13FinishedMessage(MemoryStream buf)
        {
            TlsContext context = Context;
            SecurityParameters securityParameters = context.SecurityParameters;
            bool isServerContext = context.IsServer;

            Span<byte> verify_data = stackalloc byte[securityParameters.VerifyDataLength];
            AsyncTlsUtilities.ReadFully(verify_data, buf);

            AssertEmpty(buf);

            byte[] expected_verify_data = AsyncTlsUtilities.CalculateVerifyData(context, m_handshakeHash, !isServerContext);

            /*
             * Compare both checksums.
             */
            if (!Arrays.FixedTimeEquals(expected_verify_data, verify_data))
            {
                /*
                 * Wrong checksum in the finished message.
                 */
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }

            securityParameters.m_peerVerifyData = expected_verify_data;
            securityParameters.m_tlsUnique = null;
        }

        /// <exception cref="IOException"/>
        protected virtual async Task RaiseAlertFatalAsync(short alertDescription, string message, Exception cause)
        {
            Peer.NotifyAlertRaised(AlertLevel.fatal, alertDescription, message, cause);

            byte[] alert = new byte[]{ (byte)AlertLevel.fatal, (byte)alertDescription };

            try
            {
                await m_recordStream.WriteRecordAsync(ContentType.alert, alert, 0, 2);
            }
            catch (Exception)
            {
                // We are already processing an exception, so just ignore this
            }
        }

        /// <exception cref="IOException"/>
        protected virtual async Task RaiseAlertWarningAsync(short alertDescription, string message)
        {
            Peer.NotifyAlertRaised(AlertLevel.warning, alertDescription, message, null);

            byte[] alert = new byte[]{ (byte)AlertLevel.warning, (byte)alertDescription };

            await SafeWriteRecordAsync(ContentType.alert, alert, 0, 2);
        }


        /// <exception cref="IOException"/>
        protected virtual void Receive13KeyUpdate(MemoryStream buf)
        {
            // TODO[tls13] This is interesting enough to notify the TlsPeer for possible logging/vetting

            if (!(m_appDataReady && m_keyUpdateEnabled))
                throw new TlsFatalAlert(AlertDescription.unexpected_message);

            short requestUpdate = AsyncTlsUtilities.ReadUint8(buf);

            AssertEmpty(buf);

            if (!KeyUpdateRequest.IsValid(requestUpdate))
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            bool updateRequested = (KeyUpdateRequest.update_requested == requestUpdate);

            AsyncTlsUtilities.Update13TrafficSecretPeer(Context);
            m_recordStream.NotifyKeyUpdateReceived();

            //this.m_keyUpdatePendingReceive &= updateRequested;
            this.m_keyUpdatePendingSend |= updateRequested;
        }

        /// <exception cref="IOException"/>
        protected virtual async Task SendCertificateMessageAsync(Certificate certificate, Stream endPointHash)
        {
            TlsContext context = Context;
            SecurityParameters securityParameters = context.SecurityParameters;
            if (null != securityParameters.LocalCertificate)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            if (null == certificate)
            {
                certificate = Certificate.EmptyChain;
            }

            if (certificate.IsEmpty && !context.IsServer && securityParameters.NegotiatedVersion.IsSsl)
            {
                string message = "SSLv3 client didn't provide credentials";
                await RaiseAlertWarningAsync(AlertDescription.no_certificate, message);
            }
            else
            {
                AsyncHandshakeMessageOutput message = new AsyncHandshakeMessageOutput(HandshakeType.certificate);
                certificate.Encode(context, message, endPointHash);
                await message.SendAsync(this);
            }

            securityParameters.m_localCertificate = certificate;
        }

        /// <exception cref="IOException"/>
        protected virtual async Task Send13CertificateMessageAsync(Certificate certificate)
        {
            if (null == certificate)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            TlsContext context = Context;
            SecurityParameters securityParameters = context.SecurityParameters;
            if (null != securityParameters.LocalCertificate)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            AsyncHandshakeMessageOutput message = new AsyncHandshakeMessageOutput(HandshakeType.certificate);
            certificate.Encode(context, message, null);
            await message.SendAsync(this);

            securityParameters.m_localCertificate = certificate;
        }

        /// <exception cref="IOException"/>
        protected virtual Task Send13CertificateVerifyMessageAsync(DigitallySigned certificateVerify)
        {
            AsyncHandshakeMessageOutput message = new AsyncHandshakeMessageOutput(HandshakeType.certificate_verify);
            certificateVerify.Encode(message);
            return message.SendAsync(this);
        }

        /// <exception cref="IOException"/>
        protected virtual async Task SendChangeCipherSpecAsync()
        {
            await SendChangeCipherSpecMessageAsync();
            m_recordStream.EnablePendingCipherWrite();
        }

        /// <exception cref="IOException"/>
        protected virtual async Task SendChangeCipherSpecMessageAsync()
        {
            byte[] message = new byte[]{ 1 };
            await SafeWriteRecordAsync(ContentType.change_cipher_spec, message, 0, message.Length);
        }

        /// <exception cref="IOException"/>
        protected virtual async Task SendFinishedMessageAsync()
        {
            TlsContext context = Context;
            SecurityParameters securityParameters = context.SecurityParameters;
            bool isServerContext = context.IsServer;

            byte[] verify_data = AsyncTlsUtilities.CalculateVerifyData(context, m_handshakeHash, isServerContext);

            securityParameters.m_localVerifyData = verify_data;

            if (!securityParameters.IsResumedSession || securityParameters.IsExtendedMasterSecret)
            {
                if (null == securityParameters.PeerVerifyData)
                {
                    securityParameters.m_tlsUnique = verify_data;
                }
            }

            await AsyncHandshakeMessageOutput.Send(this, HandshakeType.finished, verify_data);
        }

        /// <exception cref="IOException"/>
        protected virtual async Task Send13FinishedMessageAsync()
        {
            TlsContext context = Context;
            SecurityParameters securityParameters = context.SecurityParameters;
            bool isServerContext = context.IsServer;

            byte[] verify_data = AsyncTlsUtilities.CalculateVerifyData(context, m_handshakeHash, isServerContext);

            securityParameters.m_localVerifyData = verify_data;
            securityParameters.m_tlsUnique = null;

            await AsyncHandshakeMessageOutput.Send(this, HandshakeType.finished, verify_data);

            securityParameters.m_resumption_secret = AsyncTlsUtilities.DeriveSecret(securityParameters, securityParameters.MasterSecret, "res master", m_handshakeHash.ForkPrfHash().CalculateHash());
        }

        /// <exception cref="IOException"/>
        protected virtual async Task Send13KeyUpdateAsync(bool updateRequested)
        {
            // TODO[tls13] This is interesting enough to notify the TlsPeer for possible logging/vetting

            if (!(m_appDataReady && m_keyUpdateEnabled))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            short requestUpdate = updateRequested
                ? KeyUpdateRequest.update_requested
                : KeyUpdateRequest.update_not_requested;

            await AsyncHandshakeMessageOutput.Send(this, HandshakeType.key_update, AsyncTlsUtilities.EncodeUint8(requestUpdate));

            AsyncTlsUtilities.Update13TrafficSecretLocal(Context);
            m_recordStream.NotifyKeyUpdateSent();

            //this.m_keyUpdatePendingReceive |= updateRequested;
            this.m_keyUpdatePendingSend &= updateRequested;
        }

        /// <exception cref="IOException"/>
        protected virtual async Task SendSupplementalDataMessageAsync(IList<SupplementalDataEntry> supplementalData)
        {
            AsyncHandshakeMessageOutput message = new AsyncHandshakeMessageOutput(HandshakeType.supplemental_data);
            WriteSupplementalData(message, supplementalData);
            await message.SendAsync(this);
        }

        public virtual Task CloseAsync()
        {
            return HandleCloseAsync(true);
        }

        public virtual void Flush()
        {
        }

        internal bool IsApplicationDataReady
        {
            get { return m_appDataReady; }
        }

        public virtual bool IsClosed
        {
            get { return m_closed; }
        }

        public virtual bool IsConnected
        {
            get
            {
                if (m_closed)
                    return false;

                AbstractTlsContext context = ContextAdmin;

                return null != context && context.IsConnected;
            }
        }

        public virtual bool IsHandshaking
        {
            get
            {
                if (m_closed)
                    return false;

                AbstractTlsContext context = ContextAdmin;

                return null != context && context.IsHandshaking;
            }
        }

        /// <exception cref="IOException"/>
        [Obsolete("Will be removed")]
        protected virtual short ProcessMaxFragmentLengthExtension(IDictionary<int, byte[]> clientExtensions,
            IDictionary<int, byte[]> serverExtensions, short alertDescription)
        {
            return AsyncTlsUtilities.ProcessMaxFragmentLengthExtension(clientExtensions, serverExtensions, alertDescription);
        }

        /// <exception cref="IOException"/>
        protected virtual async Task RefuseRenegotiationAsync()
        {
            /*
             * RFC 5746 4.5 SSLv3 clients [..] SHOULD use a fatal handshake_failure alert.
             */
            if (AsyncTlsUtilities.IsSsl(Context))
                throw new TlsFatalAlert(AlertDescription.handshake_failure);

            await RaiseAlertWarningAsync(AlertDescription.no_renegotiation, "Renegotiation not supported");
        }

        /// <summary>Make sure the <see cref="Stream"/> 'buf' is now empty. Fail otherwise.</summary>
        /// <param name="buf">The <see cref="Stream"/> to check.</param>
        /// <exception cref="IOException"/>
        internal static void AssertEmpty(Stream buf)
        {
            if (buf.Position < buf.Length)
                throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        internal static byte[] CreateRandomBlock(bool useGmtUnixTime, TlsContext context)
        {
            byte[] result = context.NonceGenerator.GenerateNonce(32);

            if (useGmtUnixTime)
            {
                AsyncTlsUtilities.WriteGmtUnixTime(result, 0);
            }

            return result;
        }

        /// <exception cref="IOException"/>
        internal static byte[] CreateRenegotiationInfo(byte[] renegotiated_connection)
        {
            return AsyncTlsUtilities.EncodeOpaque8(renegotiated_connection);
        }

        /// <exception cref="IOException"/>
        internal static void EstablishMasterSecret(TlsContext context, TlsKeyExchange keyExchange)
        {
            TlsSecret preMasterSecret = keyExchange.GeneratePreMasterSecret();
            if (preMasterSecret == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            try
            {
                context.SecurityParameters.m_masterSecret = AsyncTlsUtilities.CalculateMasterSecret(context,
                    preMasterSecret);
            }
            finally
            {
                /*
                 * RFC 2246 8.1. The pre_master_secret should be deleted from memory once the
                 * master_secret has been computed.
                 */
                preMasterSecret.Destroy();
            }
        }

        /// <exception cref="IOException"/>
        internal static IDictionary<int, byte[]> ReadExtensions(MemoryStream input)
        {
            if (input.Position >= input.Length)
                return null;

            byte[] extBytes = AsyncTlsUtilities.ReadOpaque16(input);

            AssertEmpty(input);

            return ReadExtensionsData(extBytes);
        }

        /// <exception cref="IOException"/>
        internal static IDictionary<int, byte[]> ReadExtensionsData(byte[] extBytes)
        {
            // Int32 -> byte[]
            var extensions = new Dictionary<int, byte[]>();

            if (extBytes.Length > 0)
            {
                MemoryStream buf = new MemoryStream(extBytes, false);

                do
                {
                    int extension_type = AsyncTlsUtilities.ReadUint16(buf);
                    byte[] extension_data = AsyncTlsUtilities.ReadOpaque16(buf);

                    /*
                     * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
                     */
                    if (extensions.ContainsKey(extension_type))
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                            "Repeated extension: " + ExtensionType.GetText(extension_type));

                    extensions.Add(extension_type, extension_data);
                }
                while (buf.Position < buf.Length);
            }

            return extensions;
        }

        /// <exception cref="IOException"/>
        internal static IDictionary<int, byte[]> ReadExtensionsData13(int handshakeType, byte[] extBytes)
        {
            // Int32 -> byte[]
            var extensions = new Dictionary<int, byte[]>();

            if (extBytes.Length > 0)
            {
                MemoryStream buf = new MemoryStream(extBytes, false);

                do
                {
                    int extension_type = AsyncTlsUtilities.ReadUint16(buf);

                    if (!AsyncTlsUtilities.IsPermittedExtensionType13(handshakeType, extension_type))
                    {
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                            "Invalid extension: " + ExtensionType.GetText(extension_type));
                    }

                    byte[] extension_data = AsyncTlsUtilities.ReadOpaque16(buf);

                    /*
                     * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
                     */
                    if (extensions.ContainsKey(extension_type))
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                            "Repeated extension: " + ExtensionType.GetText(extension_type));

                    extensions.Add(extension_type, extension_data);
                }
                while (buf.Position < buf.Length);
            }

            return extensions;
        }

        /// <exception cref="IOException"/>
        internal static IDictionary<int, byte[]> ReadExtensionsDataClientHello(byte[] extBytes)
        {
            /*
             * TODO[tls13] We are currently allowing any extensions to appear in ClientHello. It is
             * somewhat complicated to restrict what can appear based on the specific set of versions
             * the client is offering, and anyway could be fragile since clients may take a
             * "kitchen sink" approach to adding extensions independently of the offered versions.
             */

            // Int32 -> byte[]
            var extensions = new Dictionary<int, byte[]>();

            if (extBytes.Length > 0)
            {
                MemoryStream buf = new MemoryStream(extBytes, false);

                int extension_type;
                bool pre_shared_key_found = false;

                do
                {
                    extension_type = AsyncTlsUtilities.ReadUint16(buf);
                    byte[] extension_data = AsyncTlsUtilities.ReadOpaque16(buf);

                    /*
                     * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
                     */
                    if (extensions.ContainsKey(extension_type))
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                            "Repeated extension: " + ExtensionType.GetText(extension_type));

                    extensions.Add(extension_type, extension_data);

                    pre_shared_key_found |= (ExtensionType.pre_shared_key == extension_type);
                }
                while (buf.Position < buf.Length);

                if (pre_shared_key_found && (ExtensionType.pre_shared_key != extension_type))
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                        "'pre_shared_key' MUST be last in ClientHello");
            }

            return extensions;
        }

        /// <exception cref="IOException"/>
        internal static IList<SupplementalDataEntry> ReadSupplementalDataMessage(MemoryStream input)
        {
            byte[] supp_data = AsyncTlsUtilities.ReadOpaque24(input, 1);

            AssertEmpty(input);

            MemoryStream buf = new MemoryStream(supp_data, false);

            var supplementalData = new List<SupplementalDataEntry>();

            while (buf.Position < buf.Length)
            {
                int supp_data_type = AsyncTlsUtilities.ReadUint16(buf);
                byte[] data = AsyncTlsUtilities.ReadOpaque16(buf);

                supplementalData.Add(new SupplementalDataEntry(supp_data_type, data));
            }

            return supplementalData;
        }

        /// <exception cref="IOException"/>
        internal static void WriteExtensions(Stream output, IDictionary<int, byte[]> extensions)
        {
            WriteExtensions(output, extensions, 0);
        }

        /// <exception cref="IOException"/>
        internal static void WriteExtensions(Stream output, IDictionary<int, byte[]> extensions, int bindersSize)
        {
            if (null == extensions || extensions.Count < 1)
                return;

            byte[] extBytes = WriteExtensionsData(extensions, bindersSize);

            int lengthWithBinders = extBytes.Length + bindersSize;
            AsyncTlsUtilities.CheckUint16(lengthWithBinders);
            AsyncTlsUtilities.WriteUint16(lengthWithBinders, output);
            output.Write(extBytes, 0, extBytes.Length);
        }

        /// <exception cref="IOException"/>
        internal static byte[] WriteExtensionsData(IDictionary<int, byte[]> extensions)
        {
            return WriteExtensionsData(extensions, 0);
        }

        /// <exception cref="IOException"/>
        internal static byte[] WriteExtensionsData(IDictionary<int, byte[]> extensions, int bindersSize)
        {
            MemoryStream buf = new MemoryStream();
            WriteExtensionsData(extensions, buf, bindersSize);
            return buf.ToArray();
        }

        /// <exception cref="IOException"/>
        internal static void WriteExtensionsData(IDictionary<int, byte[]> extensions, MemoryStream buf)
        {
            WriteExtensionsData(extensions, buf, 0);
        }

        /// <exception cref="IOException"/>
        internal static void WriteExtensionsData(IDictionary<int, byte[]> extensions, MemoryStream buf, int bindersSize)
        {
            /*
             * NOTE: There are reports of servers that don't accept a zero-length extension as the last
             * one, so we write out any zero-length ones first as a best-effort workaround.
             */
            WriteSelectedExtensions(buf, extensions, true);
            WriteSelectedExtensions(buf, extensions, false);
            WritePreSharedKeyExtension(buf, extensions, bindersSize);
        }

        /// <exception cref="IOException"/>
        internal static void WritePreSharedKeyExtension(MemoryStream buf, IDictionary<int, byte[]> extensions,
            int bindersSize)
        {
            if (extensions.TryGetValue(ExtensionType.pre_shared_key, out var extension_data))
            {
                AsyncTlsUtilities.CheckUint16(ExtensionType.pre_shared_key);
                AsyncTlsUtilities.WriteUint16(ExtensionType.pre_shared_key, buf);

                int lengthWithBinders = extension_data.Length + bindersSize;
                AsyncTlsUtilities.CheckUint16(lengthWithBinders);
                AsyncTlsUtilities.WriteUint16(lengthWithBinders, buf);
                buf.Write(extension_data, 0, extension_data.Length);
            }
        }

        /// <exception cref="IOException"/>
        internal static void WriteSelectedExtensions(Stream output, IDictionary<int, byte[]> extensions,
            bool selectEmpty)
        {
            foreach (var extension in extensions)
            {
                int extension_type = extension.Key;

                // NOTE: Must be last; handled by 'WritePreSharedKeyExtension'
                if (ExtensionType.pre_shared_key == extension_type)
                    continue;

                byte[] extension_data = extension.Value;

                if (selectEmpty == (extension_data.Length == 0))
                {
                    AsyncTlsUtilities.CheckUint16(extension_type);
                    AsyncTlsUtilities.WriteUint16(extension_type, output);
                    AsyncTlsUtilities.WriteOpaque16(extension_data, output);
                }
            }
        }

        /// <exception cref="IOException"/>
        internal static void WriteSupplementalData(Stream output, IList<SupplementalDataEntry> supplementalData)
        {
            using MemoryStream buf = new MemoryStream();

            foreach (SupplementalDataEntry entry in supplementalData)
            {
                int supp_data_type = entry.DataType;
                AsyncTlsUtilities.CheckUint16(supp_data_type);
                AsyncTlsUtilities.WriteUint16(supp_data_type, buf);
                AsyncTlsUtilities.WriteOpaque16(entry.Data, buf);
            }

            byte[] supp_data = buf.ToArray();

            AsyncTlsUtilities.WriteOpaque24(supp_data, output);
        }
    }
}
