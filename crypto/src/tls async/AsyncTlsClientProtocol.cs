using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Threading.Tasks;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Ech;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Zlib;

namespace Org.BouncyCastle.Tls.Async
{
    public class AsyncTlsClientProtocol
        : AsyncTlsProtocol
    {
        protected AsyncTlsClient m_tlsClient = null;
        internal AsyncTlsClientContextImpl m_tlsClientContext = null;

        protected IDictionary<int, TlsAgreement> m_clientAgreements = null;
        internal OfferedPsks.BindersConfig m_clientBinders = null;
        protected ClientHello m_clientHello = null;
        protected TlsKeyExchange m_keyExchange = null;
        protected TlsAuthentication m_authentication = null;

        protected CertificateStatus m_certificateStatus = null;
        protected CertificateRequest m_certificateRequest = null;

        /// <summary>Constructor for blocking mode.</summary>
        /// <param name="stream">The <see cref="Stream"/> of data to/from the server.</param>
        public AsyncTlsClientProtocol(Stream stream)
            : base(stream)
        {
        }

        /// <summary>Initiates a TLS handshake in the role of client.</summary>
        /// <remarks>
        /// In blocking mode, this will not return until the handshake is complete. In non-blocking mode, use
        /// <see cref="AsyncTlsPeer.NotifyHandshakeComplete"/> to receive a callback when the handshake is complete.
        /// </remarks>
        /// <param name="tlsClient">The <see cref="AsyncTlsClient"/> to use for the handshake.</param>
        /// <exception cref="IOException">If in blocking mode and handshake was not successful.</exception>
        public virtual async Task ConnectAsync(AsyncTlsClient tlsClient)
        {
            if (tlsClient == null)
                throw new ArgumentNullException("tlsClient");
            if (m_tlsClient != null)
                throw new InvalidOperationException("'Connect' can only be called once");

            this.m_tlsClient = tlsClient;
            this.m_tlsClientContext = new AsyncTlsClientContextImpl(tlsClient.Crypto);

            tlsClient.Init(m_tlsClientContext);
            tlsClient.NotifyCloseHandle(this);

            await BeginHandshakeAsync();

            await BlockForHandshakeAsync();
        }

        protected override async Task BeginHandshakeAsync()
        {
            await base.BeginHandshakeAsync();

            await SendClientHelloAsync();
            this.m_connectionState = CS_CLIENT_HELLO;
        }

        protected override void CleanupHandshake()
        {
            base.CleanupHandshake();

            this.m_clientAgreements = null;
            this.m_clientBinders = null;
            this.m_clientHello = null;
            this.m_keyExchange = null;
            this.m_authentication = null;

            this.m_certificateStatus = null;
            this.m_certificateRequest = null;
        }

        protected override TlsContext Context
        {
            get { return m_tlsClientContext; }
        }

        internal override AbstractTlsContext ContextAdmin
        {
            get { return m_tlsClientContext; }
        }

        protected override AsyncTlsPeer Peer
        {
            get { return m_tlsClient; }
        }

        /// <exception cref="IOException"/>
        protected virtual async Task Handle13HandshakeMessageAsync(short type, HandshakeMessageInput buf)
        {
            if (!IsTlsV13ConnectionState())
                throw new TlsFatalAlert(AlertDescription.internal_error);

            switch (type)
            {
                case HandshakeType.certificate:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_ENCRYPTED_EXTENSIONS:
                            case CS_SERVER_CERTIFICATE_REQUEST:
                                {
                                    if (m_connectionState != CS_SERVER_CERTIFICATE_REQUEST)
                                    {
                                        Skip13CertificateRequest();
                                    }

                                    Receive13ServerCertificate(buf);
                                    this.m_connectionState = CS_SERVER_CERTIFICATE;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.compressed_certificate:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_ENCRYPTED_EXTENSIONS:
                            case CS_SERVER_CERTIFICATE_REQUEST:
                                {
                                    if (m_connectionState != CS_SERVER_CERTIFICATE_REQUEST)
                                    {
                                        Skip13CertificateRequest();
                                    }

                                    var algo = AsyncTlsUtilities.ReadUint16(buf);

                                    buf.Position += 6;

                                    Stream decompress = algo switch
                                    {
                                        1 => new ZLibStream(buf, CompressionMode.Decompress, false),
                                        2 => new BrotliStream(buf, CompressionMode.Decompress, false),
                                        _ => throw new TlsFatalAlert(AlertDescription.unsupported_certificate, "Unsupported compression method")
                                    };

                                    Receive13ServerCertificate(decompress);
                                    this.m_connectionState = CS_SERVER_CERTIFICATE;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.certificate_request:
                    {
                        switch (m_connectionState)
                        {
                            case CS_END:
                                {
                                    // TODO[tls13] Permit post-handshake authentication if we sent post_handshake_auth extension
                                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                }
                            case CS_SERVER_ENCRYPTED_EXTENSIONS:
                                {
                                    Receive13CertificateRequest(buf, false);
                                    this.m_connectionState = CS_SERVER_CERTIFICATE_REQUEST;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.certificate_verify:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_CERTIFICATE:
                                {
                                    Receive13ServerCertificateVerify(buf);
                                    buf.UpdateHash(m_handshakeHash);
                                    this.m_connectionState = CS_SERVER_CERTIFICATE_VERIFY;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.encrypted_extensions:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_HELLO:
                                {
                                    Receive13EncryptedExtensions(buf);
                                    this.m_connectionState = CS_SERVER_ENCRYPTED_EXTENSIONS;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.finished:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_ENCRYPTED_EXTENSIONS:
                            case CS_SERVER_CERTIFICATE_REQUEST:
                            case CS_SERVER_CERTIFICATE_VERIFY:
                                {
                                    if (m_connectionState == CS_SERVER_ENCRYPTED_EXTENSIONS)
                                    {
                                        Skip13CertificateRequest();
                                    }
                                    if (m_connectionState != CS_SERVER_CERTIFICATE_VERIFY)
                                    {
                                        Skip13ServerCertificate();
                                    }

                                    Receive13ServerFinished(buf);
                                    buf.UpdateHash(m_handshakeHash);
                                    this.m_connectionState = CS_SERVER_FINISHED;

                                    byte[] serverFinishedTranscriptHash = AsyncTlsUtilities.GetCurrentPrfHash(m_handshakeHash);

                                    // See RFC 8446 D.4.
                                    m_recordStream.SetIgnoreChangeCipherSpec(false);

                                    /*
                                     * TODO[tls13] After receiving the server's Finished message, if the server has accepted early
                                     * data, an EndOfEarlyData message will be sent to indicate the key change. This message will
                                     * be encrypted with the 0-RTT traffic keys.
                                     */

                                    if (null != m_certificateRequest)
                                    {
                                        TlsCredentialedSigner clientCredentials = AsyncTlsUtilities.Establish13ClientCredentials(
                                            m_authentication, m_certificateRequest);

                                        Certificate clientCertificate = null;
                                        if (null != clientCredentials)
                                        {
                                            clientCertificate = clientCredentials.Certificate;
                                        }

                                        if (null == clientCertificate)
                                        {
                                            // In this calling context, certificate_request_context is length 0
                                            clientCertificate = Certificate.EmptyChainTls13;
                                        }

                                        await Send13CertificateMessageAsync(clientCertificate);
                                        this.m_connectionState = CS_CLIENT_CERTIFICATE;

                                        if (null != clientCredentials)
                                        {
                                            DigitallySigned certificateVerify = AsyncTlsUtilities.Generate13CertificateVerify(
                                                m_tlsClientContext, clientCredentials, m_handshakeHash);
                                            await Send13CertificateVerifyMessageAsync(certificateVerify);
                                            this.m_connectionState = CS_CLIENT_CERTIFICATE_VERIFY;
                                        }
                                    }

                                    await Send13FinishedMessageAsync();
                                    this.m_connectionState = CS_CLIENT_FINISHED;

                                    AsyncTlsUtilities.Establish13PhaseApplication(m_tlsClientContext, serverFinishedTranscriptHash,
                                        m_recordStream);

                                    m_recordStream.EnablePendingCipherWrite();
                                    m_recordStream.EnablePendingCipherRead(false);

                                    CompleteHandshake();
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.key_update:
                    {
                        Receive13KeyUpdate(buf);
                        break;
                    }
                case HandshakeType.new_session_ticket:
                    {
                        Receive13NewSessionTicket(buf);
                        break;
                    }
                case HandshakeType.server_hello:
                    {
                        switch (m_connectionState)
                        {
                            case CS_CLIENT_HELLO:
                                {
                                    // NOTE: Legacy handler should be dispatching initial ServerHello/HelloRetryRequest.
                                    throw new TlsFatalAlert(AlertDescription.internal_error);
                                }
                            case CS_CLIENT_HELLO_RETRY:
                                {
                                    ServerHello serverHello = ReceiveServerHelloMessage(buf);
                                    if (serverHello.IsHelloRetryRequest())
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);

                                    Process13ServerHello(serverHello, true);
                                    buf.UpdateHash(m_handshakeHash);
                                    this.m_connectionState = CS_SERVER_HELLO;

                                    await Process13ServerHelloCodaAsync(serverHello, true);
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }

                case HandshakeType.certificate_status:
                case HandshakeType.certificate_url:
                case HandshakeType.client_hello:
                case HandshakeType.client_key_exchange:
                case HandshakeType.end_of_early_data:
                case HandshakeType.hello_request:
                case HandshakeType.hello_verify_request:
                case HandshakeType.message_hash:
                case HandshakeType.server_hello_done:
                case HandshakeType.server_key_exchange:
                case HandshakeType.supplemental_data:
                default:
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        protected override async Task HandleHandshakeMessageAsync(short type, HandshakeMessageInput buf)
        {
            SecurityParameters securityParameters = m_tlsClientContext.SecurityParameters;

            if (m_connectionState > CS_CLIENT_HELLO
                && AsyncTlsUtilities.IsTlsV13(securityParameters.NegotiatedVersion))
            {
                if (securityParameters.IsResumedSession)
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                await Handle13HandshakeMessageAsync(type, buf);
                return;
            }

            if (!IsLegacyConnectionState())
                throw new TlsFatalAlert(AlertDescription.internal_error);

            if (securityParameters.IsResumedSession && type != HandshakeType.hello_request)
            {
                if (type != HandshakeType.finished || m_connectionState != CS_SERVER_HELLO)
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);

                ProcessFinishedMessage(buf);
                buf.UpdateHash(m_handshakeHash);
                this.m_connectionState = CS_SERVER_FINISHED;

                await SendChangeCipherSpecAsync();
                await SendFinishedMessageAsync();
                this.m_connectionState = CS_CLIENT_FINISHED;

                CompleteHandshake();
                return;
            }

            switch (type)
            {
                case HandshakeType.certificate:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_HELLO:
                            case CS_SERVER_SUPPLEMENTAL_DATA:
                                {
                                    if (m_connectionState != CS_SERVER_SUPPLEMENTAL_DATA)
                                    {
                                        HandleSupplementalData(null);
                                    }

                                    /*
                                     * NOTE: Certificate processing (including authentication) is delayed to allow for a
                                     * possible CertificateStatus message.
                                     */
                                    m_authentication = AsyncTlsUtilities.ReceiveServerCertificate(m_tlsClientContext, m_tlsClient, buf,
                                        m_serverExtensions);
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.m_connectionState = CS_SERVER_CERTIFICATE;
                        break;
                    }
                case HandshakeType.certificate_status:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_CERTIFICATE:
                                {
                                    if (securityParameters.StatusRequestVersion < 1)
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);

                                    this.m_certificateStatus = CertificateStatus.Parse(m_tlsClientContext, buf);

                                    AssertEmpty(buf);

                                    this.m_connectionState = CS_SERVER_CERTIFICATE_STATUS;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.finished:
                    {
                        switch (m_connectionState)
                        {
                            case CS_CLIENT_FINISHED:
                            case CS_SERVER_SESSION_TICKET:
                                {
                                    if (m_connectionState != CS_SERVER_SESSION_TICKET)
                                    {
                                        /*
                                         * RFC 5077 3.3. This message MUST be sent if the server included a
                                         * SessionTicket extension in the ServerHello.
                                         */
                                        if (m_expectSessionTicket)
                                            throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                    }

                                    ProcessFinishedMessage(buf);
                                    this.m_connectionState = CS_SERVER_FINISHED;

                                    CompleteHandshake();
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.server_hello:
                    {
                        switch (m_connectionState)
                        {
                            case CS_CLIENT_HELLO:
                                {
                                    ServerHello serverHello = ReceiveServerHelloMessage(buf);

                                    // TODO[tls13] Only treat as HRR if it's TLS 1.3??
                                    if (serverHello.IsHelloRetryRequest())
                                    {
                                        Process13HelloRetryRequest(serverHello);
                                        m_handshakeHash.NotifyPrfDetermined();
                                        m_handshakeHash.SealHashAlgorithms();
                                        AsyncTlsUtilities.AdjustTranscriptForRetry(m_handshakeHash);
                                        buf.UpdateHash(m_handshakeHash);
                                        this.m_connectionState = CS_SERVER_HELLO_RETRY_REQUEST;

                                        await Send13ClientHelloRetryAsync();
                                        this.m_connectionState = CS_CLIENT_HELLO_RETRY;
                                    }
                                    else
                                    {
                                        ProcessServerHello(serverHello);
                                        m_handshakeHash.NotifyPrfDetermined();
                                        if (AsyncTlsUtilities.IsTlsV13(securityParameters.NegotiatedVersion))
                                        {
                                            m_handshakeHash.SealHashAlgorithms();
                                        }
                                        buf.UpdateHash(m_handshakeHash);
                                        this.m_connectionState = CS_SERVER_HELLO;

                                        if (AsyncTlsUtilities.IsTlsV13(securityParameters.NegotiatedVersion))
                                        {
                                            await Process13ServerHelloCodaAsync(serverHello, false);
                                        }
                                    }

                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.supplemental_data:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_HELLO:
                                {
                                    HandleSupplementalData(ReadSupplementalDataMessage(buf));
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.server_hello_done:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_HELLO:
                            case CS_SERVER_SUPPLEMENTAL_DATA:
                            case CS_SERVER_CERTIFICATE:
                            case CS_SERVER_CERTIFICATE_STATUS:
                            case CS_SERVER_KEY_EXCHANGE:
                            case CS_SERVER_CERTIFICATE_REQUEST:
                                {
                                    if (m_connectionState == CS_SERVER_HELLO)
                                    {
                                        HandleSupplementalData(null);
                                    }
                                    if (m_connectionState == CS_SERVER_HELLO ||
                                        m_connectionState == CS_SERVER_SUPPLEMENTAL_DATA)
                                    {
                                        this.m_authentication = null;
                                    }
                                    if (m_connectionState != CS_SERVER_KEY_EXCHANGE &&
                                        m_connectionState != CS_SERVER_CERTIFICATE_REQUEST)
                                    {
                                        HandleServerCertificate();

                                        // There was no server key exchange message; check it's OK
                                        m_keyExchange.SkipServerKeyExchange();
                                    }

                                    AssertEmpty(buf);

                                    this.m_connectionState = CS_SERVER_HELLO_DONE;

                                    TlsCredentials clientAuthCredentials = null;
                                    TlsCredentialedSigner clientAuthSigner = null;
                                    Certificate clientAuthCertificate = null;
                                    SignatureAndHashAlgorithm clientAuthAlgorithm = null;
                                    TlsStreamSigner clientAuthStreamSigner = null;

                                    if (m_certificateRequest != null)
                                    {
                                        clientAuthCredentials = AsyncTlsUtilities.EstablishClientCredentials(m_authentication,
                                            m_certificateRequest);
                                        if (clientAuthCredentials != null)
                                        {
                                            clientAuthCertificate = clientAuthCredentials.Certificate;

                                            if (clientAuthCredentials is TlsCredentialedSigner)
                                            {
                                                clientAuthSigner = (TlsCredentialedSigner)clientAuthCredentials;
                                                clientAuthAlgorithm = AsyncTlsUtilities.GetSignatureAndHashAlgorithm(
                                                    securityParameters.NegotiatedVersion, clientAuthSigner);
                                                clientAuthStreamSigner = clientAuthSigner.GetStreamSigner();

                                                if (ProtocolVersion.TLSv12.Equals(securityParameters.NegotiatedVersion))
                                                {
                                                    AsyncTlsUtilities.VerifySupportedSignatureAlgorithm(securityParameters.ServerSigAlgs,
                                                        clientAuthAlgorithm, AlertDescription.internal_error);

                                                    if (clientAuthStreamSigner == null)
                                                    {
                                                        AsyncTlsUtilities.TrackHashAlgorithmClient(m_handshakeHash, clientAuthAlgorithm);
                                                    }
                                                }

                                                if (clientAuthStreamSigner != null)
                                                {
                                                    m_handshakeHash.ForceBuffering();
                                                }
                                            }
                                        }
                                    }

                                    m_handshakeHash.SealHashAlgorithms();

                                    if (clientAuthCredentials == null)
                                    {
                                        m_keyExchange.SkipClientCredentials();
                                    }
                                    else
                                    {
                                        m_keyExchange.ProcessClientCredentials(clientAuthCredentials);
                                    }

                                    var clientSupplementalData = m_tlsClient.GetClientSupplementalData();
                                    if (clientSupplementalData != null)
                                    {
                                        await SendSupplementalDataMessageAsync(clientSupplementalData);
                                        this.m_connectionState = CS_CLIENT_SUPPLEMENTAL_DATA;
                                    }

                                    if (m_certificateRequest != null)
                                    {
                                        await SendCertificateMessageAsync(clientAuthCertificate, null);
                                        this.m_connectionState = CS_CLIENT_CERTIFICATE;
                                    }

                                    await SendClientKeyExchangeAsync();
                                    this.m_connectionState = CS_CLIENT_KEY_EXCHANGE;

                                    bool isSsl = AsyncTlsUtilities.IsSsl(m_tlsClientContext);
                                    if (isSsl)
                                    {
                                        // NOTE: For SSLv3 (only), master_secret needed to calculate session hash
                                        EstablishMasterSecret(m_tlsClientContext, m_keyExchange);
                                    }

                                    securityParameters.m_sessionHash = AsyncTlsUtilities.GetCurrentPrfHash(m_handshakeHash);

                                    if (!isSsl)
                                    {
                                        // NOTE: For (D)TLS, session hash potentially needed for extended_master_secret
                                        EstablishMasterSecret(m_tlsClientContext, m_keyExchange);
                                    }

                                    m_recordStream.SetPendingCipher(AsyncTlsUtilities.InitCipher(m_tlsClientContext));

                                    if (clientAuthSigner != null)
                                    {
                                        DigitallySigned certificateVerify = AsyncTlsUtilities.GenerateCertificateVerifyClient(
                                            m_tlsClientContext, clientAuthSigner, clientAuthAlgorithm, clientAuthStreamSigner,
                                            m_handshakeHash);
                                        await SendCertificateVerifyMessageAsync(certificateVerify);
                                        this.m_connectionState = CS_CLIENT_CERTIFICATE_VERIFY;
                                    }

                                    m_handshakeHash.StopTracking();

                                    await SendChangeCipherSpecAsync();
                                    await SendFinishedMessageAsync();
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.m_connectionState = CS_CLIENT_FINISHED;
                        break;
                    }
                case HandshakeType.server_key_exchange:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_HELLO:
                            case CS_SERVER_SUPPLEMENTAL_DATA:
                            case CS_SERVER_CERTIFICATE:
                            case CS_SERVER_CERTIFICATE_STATUS:
                                {
                                    if (m_connectionState == CS_SERVER_HELLO)
                                    {
                                        HandleSupplementalData(null);
                                    }
                                    if (m_connectionState != CS_SERVER_CERTIFICATE &&
                                        m_connectionState != CS_SERVER_CERTIFICATE_STATUS)
                                    {
                                        this.m_authentication = null;
                                    }

                                    HandleServerCertificate();

                                    m_keyExchange.ProcessServerKeyExchange(buf);

                                    AssertEmpty(buf);
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.m_connectionState = CS_SERVER_KEY_EXCHANGE;
                        break;
                    }
                case HandshakeType.certificate_request:
                    {
                        switch (m_connectionState)
                        {
                            case CS_SERVER_CERTIFICATE:
                            case CS_SERVER_CERTIFICATE_STATUS:
                            case CS_SERVER_KEY_EXCHANGE:
                                {
                                    if (m_connectionState != CS_SERVER_KEY_EXCHANGE)
                                    {
                                        HandleServerCertificate();

                                        // There was no server key exchange message; check it's OK
                                        m_keyExchange.SkipServerKeyExchange();
                                    }

                                    ReceiveCertificateRequest(buf);

                                    AsyncTlsUtilities.EstablishServerSigAlgs(securityParameters, m_certificateRequest);
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.m_connectionState = CS_SERVER_CERTIFICATE_REQUEST;
                        break;
                    }
                case HandshakeType.new_session_ticket:
                    {
                        switch (m_connectionState)
                        {
                            case CS_CLIENT_FINISHED:
                                {
                                    if (!m_expectSessionTicket)
                                    {
                                        /*
                                         * RFC 5077 3.3. This message MUST NOT be sent if the server did not include a
                                         * SessionTicket extension in the ServerHello.
                                         */
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                    }

                                    /*
                                     * RFC 5077 3.4. If the client receives a session ticket from the server, then it
                                     * discards any Session ID that was sent in the ServerHello.
                                     */
                                    securityParameters.m_sessionID = AsyncTlsUtilities.EmptyBytes;
                                    InvalidateSession();
                                    this.m_tlsSession = AsyncTlsUtilities.ImportSession(securityParameters.SessionID, null);

                                    ReceiveNewSessionTicket(buf);
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.m_connectionState = CS_SERVER_SESSION_TICKET;
                        break;
                    }
                case HandshakeType.hello_request:
                    {
                        AssertEmpty(buf);

                        /*
                         * RFC 2246 7.4.1.1 Hello request This message will be ignored by the client if the
                         * client is currently negotiating a session. This message may be ignored by the client
                         * if it does not wish to renegotiate a session, or the client may, if it wishes,
                         * respond with a no_renegotiation alert.
                         */
                        if (IsApplicationDataReady)
                        {
                            await RefuseRenegotiationAsync();
                        }
                        break;
                    }

                case HandshakeType.certificate_url:
                case HandshakeType.certificate_verify:
                case HandshakeType.client_hello:
                case HandshakeType.client_key_exchange:
                case HandshakeType.compressed_certificate:
                case HandshakeType.encrypted_extensions:
                case HandshakeType.end_of_early_data:
                case HandshakeType.hello_verify_request:
                case HandshakeType.key_update:
                case HandshakeType.message_hash:
                default:
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void HandleServerCertificate()
        {
            AsyncTlsUtilities.ProcessServerCertificate(m_tlsClientContext, m_certificateStatus, m_keyExchange,
                m_authentication, m_clientExtensions, m_serverExtensions);
        }

        /// <exception cref="IOException"/>
        protected virtual void HandleSupplementalData(IList<SupplementalDataEntry> serverSupplementalData)
        {
            m_tlsClient.ProcessServerSupplementalData(serverSupplementalData);
            this.m_connectionState = CS_SERVER_SUPPLEMENTAL_DATA;

            this.m_keyExchange = AsyncTlsUtilities.InitKeyExchangeClient(m_tlsClientContext, m_tlsClient);
        }

        /// <exception cref="IOException"/>
        protected virtual void Process13HelloRetryRequest(ServerHello helloRetryRequest)
        {
            ProtocolVersion legacy_record_version = ProtocolVersion.TLSv12;
            m_recordStream.SetWriteVersion(legacy_record_version);

            SecurityParameters securityParameters = m_tlsClientContext.SecurityParameters;

            /*
             * RFC 8446 4.1.4. Upon receipt of a HelloRetryRequest, the client MUST check the
             * legacy_version, legacy_session_id_echo, cipher_suite, and legacy_compression_method as
             * specified in Section 4.1.3 and then process the extensions, starting with determining the
             * version using "supported_versions".
             */
            ProtocolVersion legacy_version = helloRetryRequest.Version;
            byte[] legacy_session_id_echo = helloRetryRequest.SessionID;
            int cipherSuite = helloRetryRequest.CipherSuite;
            // NOTE: legacy_compression_method checked during ServerHello parsing

            if (!ProtocolVersion.TLSv12.Equals(legacy_version) ||
                !Arrays.AreEqual(m_clientHello.SessionID, legacy_session_id_echo) ||
                !AsyncTlsUtilities.IsValidCipherSuiteSelection(m_clientHello.CipherSuites, cipherSuite))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            var extensions = helloRetryRequest.Extensions;
            if (null == extensions)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            AsyncTlsUtilities.CheckExtensionData13(extensions, HandshakeType.hello_retry_request,
                AlertDescription.illegal_parameter);

            {
                /*
                 * RFC 8446 4.2. Implementations MUST NOT send extension responses if the remote
                 * endpoint did not send the corresponding extension requests, with the exception of the
                 * "cookie" extension in the HelloRetryRequest. Upon receiving such an extension, an
                 * endpoint MUST abort the handshake with an "unsupported_extension" alert.
                 */
                foreach (int extType in extensions.Keys)
                {
                    if (ExtensionType.cookie == extType)
                        continue;

                    if (null == AsyncTlsUtilities.GetExtensionData(m_clientExtensions, extType))
                        throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                }
            }

            ProtocolVersion server_version = TlsExtensionsUtilities.GetSupportedVersionsExtensionServer(extensions);
            if (null == server_version)
                throw new TlsFatalAlert(AlertDescription.missing_extension);

            if (!ProtocolVersion.TLSv13.IsEqualOrEarlierVersionOf(server_version) ||
                !ProtocolVersion.Contains(m_tlsClientContext.ClientSupportedVersions, server_version) ||
                !AsyncTlsUtilities.IsValidVersionForCipherSuite(cipherSuite, server_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            if (null != m_clientBinders)
            {
                if (!Arrays.Contains(m_clientBinders.m_pskKeyExchangeModes, PskKeyExchangeMode.psk_dhe_ke))
                {
                    this.m_clientBinders = null;

                    m_tlsClient.NotifySelectedPsk(null);
                }
            }

            /*
             * RFC 8446 4.2.8. Upon receipt of this [Key Share] extension in a HelloRetryRequest, the
             * client MUST verify that (1) the selected_group field corresponds to a group which was
             * provided in the "supported_groups" extension in the original ClientHello and (2) the
             * selected_group field does not correspond to a group which was provided in the "key_share"
             * extension in the original ClientHello. If either of these checks fails, then the client
             * MUST abort the handshake with an "illegal_parameter" alert.
             */
            int selected_group = TlsExtensionsUtilities.GetKeyShareHelloRetryRequest(extensions);

            if (!AsyncTlsUtilities.IsValidKeyShareSelection(server_version, securityParameters.ClientSupportedGroups,
                m_clientAgreements, selected_group))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            byte[] cookie = TlsExtensionsUtilities.GetCookieExtension(extensions);



            securityParameters.m_negotiatedVersion = server_version;
            AsyncTlsUtilities.NegotiatedVersionTlsClient(m_tlsClientContext, m_tlsClient);

            securityParameters.m_resumedSession = false;
            securityParameters.m_sessionID = AsyncTlsUtilities.EmptyBytes;
            m_tlsClient.NotifySessionID(AsyncTlsUtilities.EmptyBytes);

            AsyncTlsUtilities.NegotiatedCipherSuite(securityParameters, cipherSuite);
            m_tlsClient.NotifySelectedCipherSuite(cipherSuite);

            this.m_clientAgreements = null;
            this.m_retryCookie = cookie;
            this.m_retryGroup = selected_group;
        }

        /// <exception cref="IOException"/>
        protected virtual void Process13ServerHello(ServerHello serverHello, bool afterHelloRetryRequest)
        {
            SecurityParameters securityParameters = m_tlsClientContext.SecurityParameters;

            ProtocolVersion legacy_version = serverHello.Version;
            byte[] legacy_session_id_echo = serverHello.SessionID;
            int cipherSuite = serverHello.CipherSuite;
            // NOTE: legacy_compression_method checked during ServerHello parsing

            if (!ProtocolVersion.TLSv12.Equals(legacy_version) ||
                !Arrays.AreEqual(m_clientHello.SessionID, legacy_session_id_echo))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            var extensions = serverHello.Extensions;
            if (null == extensions)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            AsyncTlsUtilities.CheckExtensionData13(extensions, HandshakeType.server_hello,
                AlertDescription.illegal_parameter);

            if (afterHelloRetryRequest)
            {
                ProtocolVersion server_version = TlsExtensionsUtilities.GetSupportedVersionsExtensionServer(extensions);
                if (null == server_version)
                    throw new TlsFatalAlert(AlertDescription.missing_extension);

                if (!securityParameters.NegotiatedVersion.Equals(server_version) ||
                    securityParameters.CipherSuite != cipherSuite)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
            else
            {
                if (!AsyncTlsUtilities.IsValidCipherSuiteSelection(m_clientHello.CipherSuites, cipherSuite) ||
                    !AsyncTlsUtilities.IsValidVersionForCipherSuite(cipherSuite, securityParameters.NegotiatedVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                securityParameters.m_resumedSession = false;
                securityParameters.m_sessionID = AsyncTlsUtilities.EmptyBytes;
                m_tlsClient.NotifySessionID(AsyncTlsUtilities.EmptyBytes);

                AsyncTlsUtilities.NegotiatedCipherSuite(securityParameters, cipherSuite);
                m_tlsClient.NotifySelectedCipherSuite(cipherSuite);
            }

            this.m_clientHello = null;

            // NOTE: Apparently downgrade marker mechanism not used for TLS 1.3+?
            securityParameters.m_serverRandom = serverHello.Random;

            securityParameters.m_secureRenegotiation = false;

            /*
             * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
             * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
             * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
             */
            securityParameters.m_extendedMasterSecret = true;

            /*
             * TODO[tls13] RFC 8446 4.4.2.1. OCSP Status and SCT Extensions.
             * 
             * OCSP information is carried in an extension for a CertificateEntry.
             */
            securityParameters.m_statusRequestVersion =
                m_clientExtensions.ContainsKey(ExtensionType.status_request) ? 1 : 0;

            TlsSecret pskEarlySecret = null;
            {
                int selected_identity = TlsExtensionsUtilities.GetPreSharedKeyServerHello(extensions);
                TlsPsk selectedPsk = null;

                if (selected_identity >= 0)
                {
                    if (null == m_clientBinders || selected_identity >= m_clientBinders.m_psks.Length)
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);

                    selectedPsk = m_clientBinders.m_psks[selected_identity];
                    if (selectedPsk.PrfAlgorithm != securityParameters.PrfAlgorithm)
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);

                    pskEarlySecret = m_clientBinders.m_earlySecrets[selected_identity];

                    this.m_selectedPsk13 = true;
                }

                m_tlsClient.NotifySelectedPsk(selectedPsk);
            }

            TlsSecret sharedSecret = null;
            {
                KeyShareEntry keyShareEntry = TlsExtensionsUtilities.GetKeyShareServerHello(extensions);
                if (null == keyShareEntry)
                {
                    if (afterHelloRetryRequest
                        || null == pskEarlySecret
                        || !Arrays.Contains(m_clientBinders.m_pskKeyExchangeModes, PskKeyExchangeMode.psk_ke))
                    {
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }
                }
                else
                {
                    if (null != pskEarlySecret
                        && !Arrays.Contains(m_clientBinders.m_pskKeyExchangeModes, PskKeyExchangeMode.psk_dhe_ke))
                    {
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }

                    if (!m_clientAgreements.TryGetValue(keyShareEntry.NamedGroup, out var agreement))
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);

                    agreement.ReceivePeerValue(keyShareEntry.KeyExchange);
                    sharedSecret = agreement.CalculateSecret();
                }
            }

            this.m_clientAgreements = null;
            this.m_clientBinders = null;

            AsyncTlsUtilities.Establish13PhaseSecrets(m_tlsClientContext, pskEarlySecret, sharedSecret);

            InvalidateSession();
            this.m_tlsSession = AsyncTlsUtilities.ImportSession(securityParameters.SessionID, null);
        }

        /// <exception cref="IOException"/>
        protected virtual async Task Process13ServerHelloCodaAsync(ServerHello serverHello, bool afterHelloRetryRequest)
        {
            byte[] serverHelloTranscriptHash = AsyncTlsUtilities.GetCurrentPrfHash(m_handshakeHash);

            AsyncTlsUtilities.Establish13PhaseHandshake(m_tlsClientContext, serverHelloTranscriptHash, m_recordStream);

            // See RFC 8446 D.4.
            if (!afterHelloRetryRequest)
            {
                m_recordStream.SetIgnoreChangeCipherSpec(true);

                /*
                 * TODO[tls13] If offering early_data, the record is placed immediately after the first
                 * ClientHello.
                 */
                /*
                 * TODO[tls13] Ideally wait until just after Server Finished received, but then we'd need to defer
                 * the enabling of the pending write cipher
                 */
                await SendChangeCipherSpecMessageAsync();
            }

            m_recordStream.EnablePendingCipherWrite();
            m_recordStream.EnablePendingCipherRead(false);
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessServerHello(ServerHello serverHello)
        {
            var serverHelloExtensions = serverHello.Extensions;

            ProtocolVersion legacy_version = serverHello.Version;
            ProtocolVersion supported_version = TlsExtensionsUtilities.GetSupportedVersionsExtensionServer(
                serverHelloExtensions);

            ProtocolVersion server_version;
            if (null == supported_version)
            {
                server_version = legacy_version;
            }
            else
            {
                if (!ProtocolVersion.TLSv12.Equals(legacy_version) ||
                    !ProtocolVersion.TLSv13.IsEqualOrEarlierVersionOf(supported_version))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                server_version = supported_version;
            }

            SecurityParameters securityParameters = m_tlsClientContext.SecurityParameters;

            // NOT renegotiating
            {
                if (!ProtocolVersion.Contains(m_tlsClientContext.ClientSupportedVersions, server_version))
                    throw new TlsFatalAlert(AlertDescription.protocol_version);

                ProtocolVersion legacy_record_version = server_version.IsLaterVersionOf(ProtocolVersion.TLSv12)
                    ? ProtocolVersion.TLSv12
                    : server_version;

                m_recordStream.SetWriteVersion(legacy_record_version);
                securityParameters.m_negotiatedVersion = server_version;
            }

            AsyncTlsUtilities.NegotiatedVersionTlsClient(m_tlsClientContext, m_tlsClient);

            if (ProtocolVersion.TLSv13.IsEqualOrEarlierVersionOf(server_version))
            {
                Process13ServerHello(serverHello, false);
                return;
            }

            int[] offeredCipherSuites = m_clientHello.CipherSuites;

            this.m_clientHello = null;
            this.m_retryCookie = null;
            this.m_retryGroup = -1;

            securityParameters.m_serverRandom = serverHello.Random;

            if (!m_tlsClientContext.ClientVersion.Equals(server_version))
            {
                AsyncTlsUtilities.CheckDowngradeMarker(server_version, securityParameters.ServerRandom);
            }

            {
                byte[] selectedSessionID = serverHello.SessionID;
                securityParameters.m_sessionID = selectedSessionID;
                m_tlsClient.NotifySessionID(selectedSessionID);
                securityParameters.m_resumedSession = selectedSessionID.Length > 0 && m_tlsSession != null
                    && Arrays.AreEqual(selectedSessionID, m_tlsSession.SessionID);

                if (securityParameters.IsResumedSession)
                {
                    if (serverHello.CipherSuite != m_sessionParameters.CipherSuite ||
                        !securityParameters.NegotiatedVersion.Equals(m_sessionParameters.NegotiatedVersion))
                    {
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                            "ServerHello parameters do not match resumed session");
                    }
                }
            }

            /*
             * Find out which CipherSuite the server has chosen and check that it was one of the offered
             * ones, and is a valid selection for the negotiated version.
             */
            {
                int cipherSuite = serverHello.CipherSuite;

                if (!AsyncTlsUtilities.IsValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                    !AsyncTlsUtilities.IsValidVersionForCipherSuite(cipherSuite, securityParameters.NegotiatedVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                        "ServerHello selected invalid cipher suite");
                }

                AsyncTlsUtilities.NegotiatedCipherSuite(securityParameters, cipherSuite);
                m_tlsClient.NotifySelectedCipherSuite(cipherSuite);
            }

            /*
             * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
             * extended client hello message.
             * 
             * However, see RFC 5746 exception below. We always include the SCSV, so an Extended Server
             * Hello is always allowed.
             */
            this.m_serverExtensions = serverHelloExtensions;
            if (serverHelloExtensions != null)
            {
                foreach (int extType in serverHelloExtensions.Keys)
                {
                    /*
                     * RFC 5746 3.6. Note that sending a "renegotiation_info" extension in response to a
                     * ClientHello containing only the SCSV is an explicit exception to the prohibition
                     * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                     * only allowed because the client is signaling its willingness to receive the
                     * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                     */
                    if (ExtensionType.renegotiation_info == extType)
                        continue;

                    /*
                     * RFC 5246 7.4.1.4 An extension type MUST NOT appear in the ServerHello unless the
                     * same extension type appeared in the corresponding ClientHello. If a client
                     * receives an extension type in ServerHello that it did not request in the
                     * associated ClientHello, it MUST abort the handshake with an unsupported_extension
                     * fatal alert.
                     */
                    if (null == AsyncTlsUtilities.GetExtensionData(m_clientExtensions, extType))
                        throw new TlsFatalAlert(AlertDescription.unsupported_extension);

                    /*
                     * RFC 3546 2.3. If [...] the older session is resumed, then the server MUST ignore
                     * extensions appearing in the client hello, and send a server hello containing no
                     * extensions[.]
                     */
                    if (securityParameters.IsResumedSession)
                    {
                        // TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
                        // TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
                        // TODO[compat-polarssl] PolarSSL test server sends server extensions e.g. ec_point_formats
                        //                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }
                }
            }

            byte[] renegExtData = AsyncTlsUtilities.GetExtensionData(serverHelloExtensions, ExtensionType.renegotiation_info);

            // NOT renegotiating
            {
                /*
                 * RFC 5746 3.4. Client Behavior: Initial Handshake (both full and session-resumption)
                 */

                /*
                 * When a ServerHello is received, the client MUST check if it includes the
                 * "renegotiation_info" extension:
                 */
                if (renegExtData == null)
                {
                    /*
                     * If the extension is not present, the server does not support secure
                     * renegotiation; set secure_renegotiation flag to FALSE. In this case, some clients
                     * may want to terminate the handshake instead of continuing; see Section 4.1 for
                     * discussion.
                     */
                    securityParameters.m_secureRenegotiation = false;
                }
                else
                {
                    /*
                     * If the extension is present, set the secure_renegotiation flag to TRUE. The
                     * client MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    securityParameters.m_secureRenegotiation = true;

                    if (!Arrays.FixedTimeEquals(renegExtData, CreateRenegotiationInfo(AsyncTlsUtilities.EmptyBytes)))
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }

            // TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
            m_tlsClient.NotifySecureRenegotiation(securityParameters.IsSecureRenegotiation);

            // extended_master_secret
            {
                bool negotiatedEms = false;

                if (TlsExtensionsUtilities.HasExtendedMasterSecretExtension(m_clientExtensions))
                {
                    negotiatedEms = TlsExtensionsUtilities.HasExtendedMasterSecretExtension(serverHelloExtensions);

                    if (AsyncTlsUtilities.IsExtendedMasterSecretOptional(server_version))
                    {
                        if (!negotiatedEms &&
                            m_tlsClient.RequiresExtendedMasterSecret())
                        {
                            throw new TlsFatalAlert(AlertDescription.handshake_failure,
                                "Extended Master Secret extension is required");
                        }
                    }
                    else
                    {
                        if (negotiatedEms)
                        {
                            throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                                "Server sent an unexpected extended_master_secret extension negotiating " + server_version);
                        }
                    }
                }

                securityParameters.m_extendedMasterSecret = negotiatedEms;
            }

            if (securityParameters.IsResumedSession &&
                securityParameters.IsExtendedMasterSecret != m_sessionParameters.IsExtendedMasterSecret)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure,
                    "Server resumed session with mismatched extended_master_secret negotiation");
            }

            /*
             * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
             * contents of this extension are irrelevant, and only the values in the new handshake
             * messages are considered.
             */
            securityParameters.m_applicationProtocol = TlsExtensionsUtilities.GetAlpnExtensionServer(
                serverHelloExtensions);
            securityParameters.m_applicationProtocolSet = true;

            var sessionClientExtensions = m_clientExtensions;
            var sessionServerExtensions = serverHelloExtensions;

            if (securityParameters.IsResumedSession)
            {
                sessionClientExtensions = null;
                sessionServerExtensions = m_sessionParameters.ReadServerExtensions();
            }

            if (sessionServerExtensions != null && sessionServerExtensions.Count > 0)
            {
                {
                    /*
                     * RFC 7366 3. If a server receives an encrypt-then-MAC request extension from a client
                     * and then selects a stream or Authenticated Encryption with Associated Data (AEAD)
                     * ciphersuite, it MUST NOT send an encrypt-then-MAC response extension back to the
                     * client.
                     */
                    bool serverSentEncryptThenMAC = TlsExtensionsUtilities.HasEncryptThenMacExtension(
                        sessionServerExtensions);
                    if (serverSentEncryptThenMAC && !AsyncTlsUtilities.IsBlockCipherSuite(securityParameters.CipherSuite))
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);

                    securityParameters.m_encryptThenMac = serverSentEncryptThenMAC;
                }

                securityParameters.m_maxFragmentLength = AsyncTlsUtilities.ProcessMaxFragmentLengthExtension(
                    sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

                securityParameters.m_truncatedHmac = TlsExtensionsUtilities.HasTruncatedHmacExtension(
                    sessionServerExtensions);

                if (!securityParameters.IsResumedSession)
                {
                    // TODO[tls13] See RFC 8446 4.4.2.1
                    if (AsyncTlsUtilities.HasExpectedEmptyExtensionData(sessionServerExtensions,
                        ExtensionType.status_request_v2, AlertDescription.illegal_parameter))
                    {
                        securityParameters.m_statusRequestVersion = 2;
                    }
                    else if (AsyncTlsUtilities.HasExpectedEmptyExtensionData(sessionServerExtensions,
                        ExtensionType.status_request, AlertDescription.illegal_parameter))
                    {
                        securityParameters.m_statusRequestVersion = 1;
                    }

                    securityParameters.m_clientCertificateType = AsyncTlsUtilities.ProcessClientCertificateTypeExtension(
                        sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);
                    securityParameters.m_serverCertificateType = AsyncTlsUtilities.ProcessServerCertificateTypeExtension(
                        sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

                    this.m_expectSessionTicket = AsyncTlsUtilities.HasExpectedEmptyExtensionData(sessionServerExtensions,
                        ExtensionType.session_ticket, AlertDescription.illegal_parameter);
                }
            }

            if (sessionClientExtensions != null)
            {
                m_tlsClient.ProcessServerExtensions(sessionServerExtensions);
            }

            ApplyMaxFragmentLengthExtension(securityParameters.MaxFragmentLength);

            if (securityParameters.IsResumedSession)
            {
                securityParameters.m_masterSecret = m_sessionMasterSecret;
                m_recordStream.SetPendingCipher(AsyncTlsUtilities.InitCipher(m_tlsClientContext));
            }
            else
            {
                InvalidateSession();
                this.m_tlsSession = AsyncTlsUtilities.ImportSession(securityParameters.SessionID, null);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void Receive13CertificateRequest(MemoryStream buf, bool postHandshakeAuth)
        {
            // TODO[tls13] Support for post_handshake_auth
            if (postHandshakeAuth)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            /* 
             * RFC 8446 4.3.2. A server which is authenticating with a certificate MAY optionally
             * request a certificate from the client.
             */

            if (m_selectedPsk13)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);

            CertificateRequest certificateRequest = CertificateRequest.Parse(m_tlsClientContext, buf);

            AssertEmpty(buf);

            if (!certificateRequest.HasCertificateRequestContext(AsyncTlsUtilities.EmptyBytes))
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            this.m_certificateRequest = certificateRequest;

            AsyncTlsUtilities.EstablishServerSigAlgs(m_tlsClientContext.SecurityParameters, certificateRequest);
        }

        /// <exception cref="IOException"/>
        protected virtual void Receive13EncryptedExtensions(MemoryStream buf)
        {
            byte[] extBytes = AsyncTlsUtilities.ReadOpaque16(buf);

            AssertEmpty(buf);


            this.m_serverExtensions = ReadExtensionsData13(HandshakeType.encrypted_extensions, extBytes);

            {
                /*
                 * RFC 8446 4.2. Implementations MUST NOT send extension responses if the remote
                 * endpoint did not send the corresponding extension requests, with the exception of the
                 * "cookie" extension in the HelloRetryRequest. Upon receiving such an extension, an
                 * endpoint MUST abort the handshake with an "unsupported_extension" alert.
                 */
                foreach (int extType in m_serverExtensions.Keys)
                {
                    if (null == AsyncTlsUtilities.GetExtensionData(m_clientExtensions, extType))
                        throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                }
            }


            SecurityParameters securityParameters = m_tlsClientContext.SecurityParameters;
            ProtocolVersion negotiatedVersion = securityParameters.NegotiatedVersion;

            securityParameters.m_applicationProtocol = TlsExtensionsUtilities.GetAlpnExtensionServer(
                m_serverExtensions);
            securityParameters.m_applicationProtocolSet = true;

            var sessionClientExtensions = m_clientExtensions;
            var sessionServerExtensions = m_serverExtensions;

            if (securityParameters.IsResumedSession)
            {
                sessionClientExtensions = null;
                sessionServerExtensions = m_sessionParameters.ReadServerExtensions();
            }

            securityParameters.m_maxFragmentLength = AsyncTlsUtilities.ProcessMaxFragmentLengthExtension(
                sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);

            securityParameters.m_encryptThenMac = false;
            securityParameters.m_truncatedHmac = false;

            if (!securityParameters.IsResumedSession)
            {
                /*
                 * TODO[tls13] RFC 8446 4.4.2.1. OCSP Status and SCT Extensions.
                 * 
                 * OCSP information is carried in an extension for a CertificateEntry.
                 */
                securityParameters.m_statusRequestVersion = m_clientExtensions.ContainsKey(ExtensionType.status_request)
                    ? 1 : 0;

                securityParameters.m_clientCertificateType = AsyncTlsUtilities.ProcessClientCertificateTypeExtension13(
                    sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);
                securityParameters.m_serverCertificateType = AsyncTlsUtilities.ProcessServerCertificateTypeExtension13(
                    sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter);
            }

            this.m_expectSessionTicket = false;

            if (null != sessionClientExtensions)
            {
                m_tlsClient.ProcessServerExtensions(m_serverExtensions);
            }

            ApplyMaxFragmentLengthExtension(securityParameters.MaxFragmentLength);
        }

        /// <exception cref="IOException"/>
        protected virtual void Receive13NewSessionTicket(MemoryStream buf)
        {
            if (!IsApplicationDataReady)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);

            var newSessionTicket = NewSessionTicket13.Parse(buf);

            AssertEmpty(buf);

            m_tlsClient.NotifyNewSessionTicket13(newSessionTicket);
        }

        /// <exception cref="IOException"/>
        protected virtual void Receive13ServerCertificate(Stream buf)
        {
            if (m_selectedPsk13)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);

            m_authentication = AsyncTlsUtilities.Receive13ServerCertificate(m_tlsClientContext, m_tlsClient, buf,
                m_serverExtensions);

            // NOTE: In TLS 1.3 we don't have to wait for a possible CertificateStatus message.
            HandleServerCertificate();
        }

        /// <exception cref="IOException"/>
        protected virtual void Receive13ServerCertificateVerify(MemoryStream buf)
        {
            Certificate serverCertificate = m_tlsClientContext.SecurityParameters.PeerCertificate;
            if (null == serverCertificate || serverCertificate.IsEmpty)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            CertificateVerify certificateVerify = CertificateVerify.Parse(m_tlsClientContext, buf);

            AssertEmpty(buf);

            AsyncTlsUtilities.Verify13CertificateVerifyServer(m_tlsClientContext, m_handshakeHash, certificateVerify);
        }

        /// <exception cref="IOException"/>
        protected virtual void Receive13ServerFinished(MemoryStream buf)
        {
            Process13FinishedMessage(buf);
        }

        /// <exception cref="IOException"/>
        protected virtual void ReceiveCertificateRequest(MemoryStream buf)
        {
            if (null == m_authentication)
            {
                /*
                 * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server to
                 * request client identification.
                 */
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            CertificateRequest certificateRequest = CertificateRequest.Parse(m_tlsClientContext, buf);

            AssertEmpty(buf);

            m_certificateRequest = AsyncTlsUtilities.ValidateCertificateRequest(certificateRequest, m_keyExchange);
        }

        /// <exception cref="IOException"/>
        protected virtual void ReceiveNewSessionTicket(MemoryStream buf)
        {
            NewSessionTicket newSessionTicket = NewSessionTicket.Parse(buf);

            AssertEmpty(buf);

            m_tlsClient.NotifyNewSessionTicket(newSessionTicket);
        }

        /// <exception cref="IOException"/>
        protected virtual ServerHello ReceiveServerHelloMessage(MemoryStream buf)
        {
            return ServerHello.Parse(buf);
        }

        /// <exception cref="IOException"/>
        protected virtual async Task Send13ClientHelloRetryAsync()
        {
            var clientHelloExtensions = m_clientHello.Extensions;

            clientHelloExtensions.Remove(ExtensionType.cookie);
            clientHelloExtensions.Remove(ExtensionType.early_data);
            clientHelloExtensions.Remove(ExtensionType.key_share);
            clientHelloExtensions.Remove(ExtensionType.pre_shared_key);

            /*
             * RFC 4.2.2. When sending the new ClientHello, the client MUST copy the contents of the
             * extension received in the HelloRetryRequest into a "cookie" extension in the new
             * ClientHello.
             */
            if (null != m_retryCookie)
            {
                /*
                 * - Including a "cookie" extension if one was provided in the HelloRetryRequest.
                 */
                TlsExtensionsUtilities.AddCookieExtension(clientHelloExtensions, m_retryCookie);
                this.m_retryCookie = null;
            }

            /*
             * - Updating the "pre_shared_key" extension if present by recomputing the "obfuscated_ticket_age"
             * and binder values and (optionally) removing any PSKs which are incompatible with the server's
             * indicated cipher suite.
             */
            if (null != m_clientBinders)
            {
                this.m_clientBinders = AsyncTlsUtilities.AddPreSharedKeyToClientHelloRetry(m_tlsClientContext,
                    m_clientBinders, clientHelloExtensions);
                if (null == m_clientBinders)
                {
                    m_tlsClient.NotifySelectedPsk(null);
                }
            }

            /*
             * RFC 8446 4.2.8. [..] when sending the new ClientHello, the client MUST replace the
             * original "key_share" extension with one containing only a new KeyShareEntry for the group
             * indicated in the selected_group field of the triggering HelloRetryRequest.
             */
            if (m_retryGroup < 0)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            /*
             * - If a "key_share" extension was supplied in the HelloRetryRequest, replacing the list of shares
             * with a list containing a single KeyShareEntry from the indicated group
             */
            this.m_clientAgreements = AsyncTlsUtilities.AddKeyShareToClientHelloRetry(m_tlsClientContext,
                clientHelloExtensions, m_retryGroup);

            /*
             * TODO[tls13] Optionally adding, removing, or changing the length of the "padding"
             * extension [RFC7685].
             */

            // See RFC 8446 D.4.
            {
                m_recordStream.SetIgnoreChangeCipherSpec(true);

                /*
                 * TODO[tls13] If offering early_data, the record is placed immediately after the first
                 * ClientHello.
                 */
                await SendChangeCipherSpecMessageAsync();
            }

            await SendClientHelloMessageAsync();
        }

        /// <exception cref="IOException"/>
        protected virtual Task SendCertificateVerifyMessageAsync(DigitallySigned certificateVerify)
        {
            AsyncHandshakeMessageOutput message = new AsyncHandshakeMessageOutput(HandshakeType.certificate_verify);
            certificateVerify.Encode(message);
            return message.SendAsync(this);
        }

        /// <exception cref="IOException"/>
        protected virtual Task SendClientHelloAsync()
        {
            SecurityParameters securityParameters = m_tlsClientContext.SecurityParameters;

            ProtocolVersion[] supportedVersions;
            ProtocolVersion earliestVersion, latestVersion;

            // NOT renegotiating
            {
                supportedVersions = m_tlsClient.GetProtocolVersions();

                if (ProtocolVersion.Contains(supportedVersions, ProtocolVersion.SSLv3))
                {
                    // TODO[tls13] Prevent offering SSLv3 AND TLSv13?
                    m_recordStream.SetWriteVersion(ProtocolVersion.SSLv3);
                }
                else
                {
                    m_recordStream.SetWriteVersion(ProtocolVersion.TLSv10);
                }

                earliestVersion = ProtocolVersion.GetEarliestTls(supportedVersions);
                latestVersion = ProtocolVersion.GetLatestTls(supportedVersions);

                if (!ProtocolVersion.IsSupportedTlsVersionClient(latestVersion))
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                m_tlsClientContext.SetClientVersion(latestVersion);
            }

            m_tlsClientContext.SetClientSupportedVersions(supportedVersions);

            bool offeringTlsV12Minus = ProtocolVersion.TLSv12.IsEqualOrLaterVersionOf(earliestVersion);
            bool offeringTlsV13Plus = ProtocolVersion.TLSv13.IsEqualOrEarlierVersionOf(latestVersion);

            {
                bool useGmtUnixTime = !offeringTlsV13Plus && m_tlsClient.ShouldUseGmtUnixTime();

                securityParameters.m_clientRandom = CreateRandomBlock(useGmtUnixTime, m_tlsClientContext);
            }

            TlsSession sessionToResume = offeringTlsV12Minus ? m_tlsClient.GetSessionToResume() : null;

            bool fallback = m_tlsClient.IsFallback();

            int[] offeredCipherSuites = m_tlsClient.GetCipherSuites();

            this.m_clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(m_tlsClient.GetClientExtensions());

            bool shouldUseEms = m_tlsClient.ShouldUseExtendedMasterSecret();

            EstablishSession(sessionToResume);

            byte[] legacy_session_id = AsyncTlsUtilities.GetSessionID(m_tlsSession);

            if (legacy_session_id.Length > 0)
            {
                if (!Arrays.Contains(offeredCipherSuites, m_sessionParameters.CipherSuite))
                {
                    legacy_session_id = AsyncTlsUtilities.EmptyBytes;
                }
            }

            ProtocolVersion sessionVersion = null;
            if (legacy_session_id.Length > 0)
            {
                sessionVersion = m_sessionParameters.NegotiatedVersion;

                if (!ProtocolVersion.Contains(supportedVersions, sessionVersion))
                {
                    legacy_session_id = AsyncTlsUtilities.EmptyBytes;
                }
            }

            if (legacy_session_id.Length > 0 && AsyncTlsUtilities.IsExtendedMasterSecretOptional(sessionVersion))
            {
                if (shouldUseEms)
                {
                    if (!m_sessionParameters.IsExtendedMasterSecret &&
                        !m_tlsClient.AllowLegacyResumption())
                    {
                        legacy_session_id = AsyncTlsUtilities.EmptyBytes;
                    }
                }
                else
                {
                    if (m_sessionParameters.IsExtendedMasterSecret)
                    {
                        legacy_session_id = AsyncTlsUtilities.EmptyBytes;
                    }
                }
            }

            if (legacy_session_id.Length < 1)
            {
                CancelSession();
            }

            m_tlsClient.NotifySessionToResume(m_tlsSession);

            ProtocolVersion legacy_version = latestVersion;
            if (offeringTlsV13Plus)
            {
                legacy_version = ProtocolVersion.TLSv12;

                TlsExtensionsUtilities.AddSupportedVersionsExtensionClient(m_clientExtensions, supportedVersions);

                /*
                 * RFC 8446 4.1.2. In compatibility mode [..], this field MUST be non-empty, so a client
                 * not offering a pre-TLS 1.3 session MUST generate a new 32-byte value.
                 */
                if (legacy_session_id.Length < 1 && AsyncTlsUtilities.ShouldUseCompatibilityMode(m_tlsClient))
                {
                    legacy_session_id = m_tlsClientContext.NonceGenerator.GenerateNonce(32);
                }
            }

            m_tlsClientContext.SetRsaPreMasterSecretVersion(legacy_version);

            securityParameters.m_clientServerNames = TlsExtensionsUtilities.GetServerNameExtensionClient(
                m_clientExtensions);

            if (AsyncTlsUtilities.IsSignatureAlgorithmsExtensionAllowed(latestVersion))
            {
                AsyncTlsUtilities.EstablishClientSigAlgs(securityParameters, m_clientExtensions);
            }

            securityParameters.m_clientSupportedGroups = TlsExtensionsUtilities.GetSupportedGroupsExtension(
                m_clientExtensions);

            this.m_clientBinders = AsyncTlsUtilities.AddPreSharedKeyToClientHello(m_tlsClientContext, m_tlsClient,
                m_clientExtensions, offeredCipherSuites);

            // TODO[tls13-psk] Perhaps don't add key_share if external PSK(s) offered and 'psk_dhe_ke' not offered  
            this.m_clientAgreements = AsyncTlsUtilities.AddKeyShareToClientHello(m_tlsClientContext, m_tlsClient,
                m_clientExtensions);

            if (shouldUseEms && AsyncTlsUtilities.IsExtendedMasterSecretOptional(supportedVersions))
            {
                TlsExtensionsUtilities.AddExtendedMasterSecretExtension(this.m_clientExtensions);
            }
            else
            {
                this.m_clientExtensions.Remove(ExtensionType.extended_master_secret);
            }

            // NOT renegotiating
            {
                /*
                 * RFC 5746 3.4. Client Behavior: Initial Handshake (both full and session-resumption)
                 */

                /*
                 * The client MUST include either an empty "renegotiation_info" extension, or the
                 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the ClientHello.
                 * Including both is NOT RECOMMENDED.
                 */
                bool noRenegExt = (null == AsyncTlsUtilities.GetExtensionData(m_clientExtensions,
                    ExtensionType.renegotiation_info));
                bool noRenegScsv = !Arrays.Contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

                if (noRenegExt && noRenegScsv)
                {
                    // TODO[tls13] Probably want to not add this if no pre-TLSv13 versions offered?
                    offeredCipherSuites = Arrays.Append(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
                }
            }

            /*
             * (Fallback SCSV)
             * RFC 7507 4. If a client sends a ClientHello.client_version containing a lower value
             * than the latest (highest-valued) version supported by the client, it SHOULD include
             * the TLS_FALLBACK_SCSV cipher suite value in ClientHello.cipher_suites [..]. (The
             * client SHOULD put TLS_FALLBACK_SCSV after all cipher suites that it actually intends
             * to negotiate.)
             */
            if (fallback && !Arrays.Contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV))
            {
                offeredCipherSuites = Arrays.Append(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV);
            }



            int bindersSize = null == m_clientBinders ? 0 : m_clientBinders.m_bindersSize;

            this.m_clientHello = new ClientHello(legacy_version, securityParameters.ClientRandom, legacy_session_id,
                cookie: null, offeredCipherSuites, m_clientExtensions, bindersSize);

            return SendClientHelloMessageAsync();
        }

        /// <exception cref="IOException"/>
        protected virtual Task SendClientHelloMessageAsync()
        {
            ClientHello innerHello = null;

            if(m_tlsClient.GetECHEnabled())
            {
                var config = m_tlsClient.GetECHConfig();

                (innerHello, m_clientHello) = ECH.OfferECH(m_clientHello, config);
            }

            AsyncHandshakeMessageOutput message = new AsyncHandshakeMessageOutput(HandshakeType.client_hello);
            m_clientHello.Encode(message);

            message.PrepareClientHello(m_handshakeHash, m_clientHello.BindersSize, innerHello == null);

            if(innerHello != null)
            {
                AsyncHandshakeMessageOutput innerMessage = new AsyncHandshakeMessageOutput(HandshakeType.client_hello);
                innerHello.Encode(innerMessage);

                innerMessage.PrepareClientHello(m_handshakeHash, m_clientHello.BindersSize, true);
            }

            if (null != m_clientBinders)
            {
                OfferedPsks.EncodeBinders(message, m_tlsClientContext.Crypto, m_handshakeHash, m_clientBinders);
            }

            return message.SendClientHelloAsync(this, m_handshakeHash, m_clientHello.BindersSize);
        }

        /// <exception cref="IOException"/>
        protected virtual Task SendClientKeyExchangeAsync()
        {
            AsyncHandshakeMessageOutput message = new AsyncHandshakeMessageOutput(HandshakeType.client_key_exchange);
            m_keyExchange.GenerateClientKeyExchange(message);
            return message.SendAsync(this);
        }

        /// <exception cref="IOException"/>
        protected virtual void Skip13CertificateRequest()
        {
            this.m_certificateRequest = null;
        }

        /// <exception cref="IOException"/>
        protected virtual void Skip13ServerCertificate()
        {
            if (!m_selectedPsk13)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);

            this.m_authentication = AsyncTlsUtilities.Skip13ServerCertificate(m_tlsClientContext);
        }
    }
}
