# Explain TLS implementations and scope

> I want to understand how the real world uses TLS. I've heard of BoringSSL and OpenSSL, but I'm sure there are way more libraries used by different applications to communicate with each other. Explain from a very low level perspective, slowly and pedagogically.&#x20;
>
> Also cover certain terminologies like&#x20;
>
> - TLS client
> - TLS library
> - TLS implementation
> - ECH-compatible TLS server
>
> The end goal of what I learn from this is to understand how much we are limiting our scope if we study fingerprinting only within a controlled TLS profile and not across many independent clients.

I’ll build this from bytes on the network up to applications and TLS libraries, then connect it to what a controlled-profile fingerprinting study can establish. I’m using the learning skill to pace the explanation and checking primary sources for the implementation and ECH details.

<details><summary>3 previous messages</summary>

> <details><summary>Explored a file, called a tool, searched the web</summary>
>
> <details><summary>Explored 2 files</summary>
>
> - Read `~/.codex/memories_v2/rollout_summaries/2026-11-01T09-34-25-rpMa-ech_strategy_review_and_layer_deployment_clarification.md`
> - Read `~/.codex/plugins/cache/claude-cowork/anthropic-skills/1.0.0/skills/learn/SKILL.md`
>
> </details>
>
> Searched the web for `site.rfc-editor.org TLS Encrypted Client Hello RFC 2026 ...`
>
> MCP tool call
>
> context7.resolve-library-id
>
> ```json
> {
>   "libraryName": "OpenSSL",
>   "query": "How libssl implements TLS over network BIO sockets and how applications configure SSL_CTX client handshakes"
> }
> ```
>
> ```text
> Available Libraries:
>
> - Title: OpenSSL
> - Context7-compatible library ID: /websites/openssl
> - Description: OpenSSL is a robust, commercial-grade, full-featured toolkit for general-purpose cryptography and secure communication.
> - Code Snippets: 20197
> - Source Reputation: High
> - Benchmark Score: 15.49
> - Versions: master
> ----------
> - Title: OpenSSL
> - Context7-compatible library ID: /openssl/openssl
> - Description: TLS/SSL and crypto library
> - Code Snippets: 7170
> - Source Reputation: High
> - Benchmark Score: 61.04
> - Versions: openssl-3.6.5
> ----------
> - Title: OpenSSL
> - Context7-compatible library ID: /websites/openssl_manmaster
> - Description: OpenSSL provides an introduction and migration guide for OpenSSL 3.0, covering core concepts, libcrypto, libssl, and FIPS 140-2 validation.
> - Code Snippets: 2
> - Source Reputation: High
> - Benchmark Score: 4.96
> ----------
> - Title: OpenSSL
> - Context7-compatible library ID: /websites/rs_openssl
> - Description: OpenSSL provides safe Rust bindings to the OpenSSL and LibreSSL cryptography libraries for secure communication, SSL/TLS, and cryptographic operations.
> - Code Snippets: 6226
> - Source Reputation: High
> - Benchmark Score: 61.84
> ----------
> - Title: OpenSSL
> - Context7-compatible library ID: /websites/rs_openssl_openssl
> - Description: OpenSSL is a Rust crate providing safe bindings to the OpenSSL cryptography library, supporting SSL/TLS, public key cryptography, digital signatures, and various cryptographic algorithms.
> - Code Snippets: 12693
> - Source Reputation: High
> - Benchmark Score: 54.65
> ```
>
> Searched the web for `https://www.rfc-editor.org/rfc/rfc9846.html`
>
> </details>
>
> The key distinction is that a TLS client is an endpoint playing a role, while a TLS library supplies code that endpoint uses. Several applications can share a library, and one application can produce different handshakes as its settings or connection history change. That makes “many clients” a more subtle test condition than simply using many program names.
>
> <details><summary>Explored a file, called a tool, searched the web</summary>
>
> MCP tool call
>
> context7.query-docs
>
> ```json
> {
>   "libraryId": "/openssl/openssl",
>   "query": "Explain the roles of libssl versus libcrypto, application SSL_CTX configuration, and SSL handshake I/O using socket or memory BIOs."
> }
> ```
>
> ````text
> ### FD
>
> Source: https://github.com/openssl/openssl/blob/master/doc/designs/ddd/README.md
>
> * FD: Whether the application creates and owns its own FD.
>   * AOSF: Application owns, calls SSL_set_fd.
>   * AOSFx: Application owns, calls SSL_set_[rw]fd, different FDs for read/write.
>   * BIOs: Application creates a socket/FD BIO and calls SSL_set_bio.
>     Application created the connection.
>   * BIOx: Application creates a BIO with a custom BIO method and calls SSL_set_bio.
>   * BIOm: Application creates a memory BIO and does its own
>     pumping to/from actual socket, treating libssl as a pure state machine which
>     does no I/O itself.
>   * BIOc: Application uses BIO_s_connect-based methods such as BIO_new_ssl_connect
>     and leaves connection establishment to OpenSSL.
>
> --------------------------------
>
> ### Memory BIO DTLS handshake loop with WANT_READ/WANT_WRITE handling
>
> Source: https://github.com/openssl/openssl/blob/master/test/helpers/ssltestlib.c
>
> Complete pattern for performing a DTLS handshake over memory BIOs. Calls SSL_connect/SSL_accept in a loop, checks SSL_get_error for SSL_ERROR_WANT_READ/SSL_ERROR_WANT_WRITE to determine when to retry, and includes DTLS-specific timeout management via OSSL_sleep() to give the DTLS retransmit timer a chance to fire. This is the standard application-level pattern for driving DTLS over memory BIOs.
>
> ```c
> int create_bare_ssl_connection_ex(SSL *serverssl, SSL *clientssl, int want,
>     int read, int listen, int *cm_count, int *sm_count)
> {
>     int retc = -1, rets = -1, err, abortctr = 0, ret = 0;
>     int clienterr = 0, servererr = 0;
>     int isdtls = SSL_is_dtls(serverssl);
>     int icm_count = 0, ism_count = 0;
>
>     do {
>         err = SSL_ERROR_WANT_WRITE;
>         while (!clienterr && retc <= 0 && err == SSL_ERROR_WANT_WRITE) {
>             retc = SSL_connect(clientssl);
>             if (retc <= 0)
>                 err = SSL_get_error(clientssl, retc);
>             icm_count++;
>         }
>
>         if (!clienterr && retc <= 0 && err != SSL_ERROR_WANT_READ) {
>             clienterr = 1;
>         }
>         if (want != SSL_ERROR_NONE && err == want)
>             goto err;
>
>         err = SSL_ERROR_WANT_WRITE;
>         while (!servererr && rets <= 0 && err == SSL_ERROR_WANT_WRITE) {
>             rets = SSL_accept(serverssl);
>             if (rets <= 0)
>                 err = SSL_get_error(serverssl, rets);
>             ism_count++;
>         }
>
>         if (!servererr && rets <= 0
>             && err != SSL_ERROR_WANT_READ
>             && err != SSL_ERROR_WANT_X509_LOOKUP) {
>             servererr = 1;
>         }
>         if (want != SSL_ERROR_NONE && err == want)
>             goto err;
>         if (clienterr && servererr)
>             goto err;
>         if (isdtls && read) {
>             unsigned char buf[20];
>             if (rets > 0 && retc <= 0) {
>                 if (SSL_read(serverssl, buf, sizeof(buf)) > 0) {
>                     goto err;
>                 }
>                 ism_count++;
>             }
>             if (retc > 0 && rets <= 0) {
>                 if (SSL_read(clientssl, buf, sizeof(buf)) > 0) {
>                     goto err;
>                 }
>                 icm_count++;
>             }
>         }
>         if (++abortctr == MAXLOOPS) {
>             goto err;
>         }
>         if (isdtls && abortctr <= 50 && (abortctr % 10) == 0) {
>             /* give the DTLS timer a chance to do something */
>             OSSL_sleep(50);
>         }
>     } while (retc <= 0 || rets <= 0);
>
>     ret = 1;
> err:
>     return ret;
> }
> ```
>
> --------------------------------
>
> ### Minimal TLS server in C using OpenSSL
>
> Source: https://github.com/openssl/openssl/wiki/Simple_TLS_Server
>
> Complete implementation of a minimal TLS server. Creates an SSL_CTX with TLS_server_method, configures certificate and private key, sets up a listening socket on port 4433, and handles each connection by performing the TLS handshake with SSL_accept and sending a test message with SSL_write. Requires cert.pem and key.pem files. Ignores SIGPIPE to avoid broken pipe signals.
>
> ```c
> #include <stdio.h>
> #include <unistd.h>
> #include <string.h>
> #include <signal.h>
> #include <sys/socket.h>
> #include <arpa/inet.h>
> #include <openssl/ssl.h>
> #include <openssl/err.h>
>
> int create_socket(int port)
> {
>     int s;
>     struct sockaddr_in addr;
>
>     addr.sin_family = AF_INET;
>     addr.sin_port = htons(port);
>     addr.sin_addr.s_addr = htonl(INADDR_ANY);
>
>     s = socket(AF_INET, SOCK_STREAM, 0);
>     if (s < 0) {
>         perror("Unable to create socket");
>         exit(EXIT_FAILURE);
>     }
>
>     if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
>         perror("Unable to bind");
>         exit(EXIT_FAILURE);
>     }
>
>     if (listen(s, 1) < 0) {
>         perror("Unable to listen");
>         exit(EXIT_FAILURE);
>     }
>
>     return s;
> }
>
> SSL_CTX *create_context()
> {
>     const SSL_METHOD *method;
>     SSL_CTX *ctx;
>
>     method = TLS_server_method();
>
>     ctx = SSL_CTX_new(method);
>     if (!ctx) {
>         perror("Unable to create SSL context");
>         ERR_print_errors_fp(stderr);
>         exit(EXIT_FAILURE);
>     }
>
>     return ctx;
> }
>
> void configure_context(SSL_CTX *ctx)
> {
>     /* Set the key and cert */
>     if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
>         ERR_print_errors_fp(stderr);
>         exit(EXIT_FAILURE);
>     }
>
>     if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
>         ERR_print_errors_fp(stderr);
>         exit(EXIT_FAILURE);
>     }
> }
>
> int main(int argc, char **argv)
> {
>     int sock;
>     SSL_CTX *ctx;
>
>     /* Ignore broken pipe signals */
>     signal(SIGPIPE, SIG_IGN);
>
>     ctx = create_context();
>
>     configure_context(ctx);
>
>     sock = create_socket(4433);
>
>     /* Handle connections */
>     while(1) {
>         struct sockaddr_in addr;
>         unsigned int len = sizeof(addr);
>         SSL *ssl;
>         const char reply[] = "test\n";
>
>         int client = accept(sock, (struct sockaddr*)&addr, &len);
>         if (client < 0) {
>             perror("Unable to accept");
>             exit(EXIT_FAILURE);
>         }
>
>         ssl = SSL_new(ctx);
>         SSL_set_fd(ssl, client);
>
>         if (SSL_accept(ssl) <= 0) {
>             ERR_print_errors_fp(stderr);
>         } else {
>             SSL_write(ssl, reply, strlen(reply));
>         }
>
>         SSL_shutdown(ssl);
>         SSL_free(ssl);
>         close(client);
>     }
>
>     close(sock);
>     SSL_CTX_free(ctx);
> }
> ```
>
> --------------------------------
>
> ### SSL_set_bio transfers ownership of the attached BIOs
>
> Source: https://github.com/openssl/openssl/blob/master/ssl/ssl_lib.c
>
> SSL_set_bio adopts the caller's references to the read/write BIOs (via SSL_set0_rbio/SSL_set0_wbio, which each free the previously attached BIO with BIO_free_all), so ownership transfers to the SSL object in all but the documented 'only rbio changed' special cases.
>
> ```c
> void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
> {
>     /*
>      * For historical reasons, this function has many different cases in
>      * ownership handling.
>      */
>
>     /* If nothing has changed, do nothing */
>     if (rbio == SSL_get_rbio(s) && wbio == SSL_get_wbio(s))
>         return;
>
>     /*
>      * If the two arguments are equal then one fewer reference is granted by the
>      * caller than we want to take
>      */
>     if (rbio != NULL && rbio == wbio) {
>         if (!BIO_up_ref(rbio))
>             return;
>     }
>
>     /*
>      * If only the wbio is changed only adopt one reference.
>      */
>     if (rbio == SSL_get_rbio(s)) {
>         SSL_set0_wbio(s, wbio);
>         return;
>     }
>     /*
>      * There is an asymmetry here for historical reasons. If only the rbio is
>      * changed AND the rbio and wbio were originally different, then we only
>      * adopt one reference.
>      */
>     if (wbio == SSL_get_wbio(s) && SSL_get_rbio(s) != SSL_get_wbio(s)) {
>         SSL_set0_rbio(s, rbio);
>         return;
>     }
>
>     /* Otherwise, adopt both references. */
>     SSL_set0_rbio(s, rbio);
>     SSL_set0_wbio(s, wbio);
> }
> ```
>
> --------------------------------
>
> ### SSL_write, SSL_write_ex
>
> Source: https://github.com/openssl/openssl/blob/master/doc/designs/quic-design/quic-api.md
>
> #### `SSL_write`, `SSL_write_ex`
>
> | Semantics | `SSL_get_error` | Can Tick? | CSHL          |
> | --------- | ------------- | --------- | ------------- |
> | Unchanged | Error/Want    | Yes       | CS            |
>
> We have to implement all of the following modes:
>
> - `SSL_MODE_ENABLE_PARTIAL_WRITE` on or off
> - `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER` on or off
> - Blocking mode on or off
>
> **Blocking Considerations:** Blocks until libssl has accepted responsibility for
> (i.e., copied) all data provided, or an error occurs, if in blocking mode. In
> other words, it blocks until it can buffer the data. This does not necessarily
> mean that the data has actually been sent.
>
> `SSL_get_stream_write_state` can be used to clarify the stream state when an
> error occurs.
> ````
>
> Searched the web for `site.rfc-editor.org "9846" TLS ...`
>
> Searched the web for `site.github.com/salesforce/ja3 "SSLVersion,Cipher,SSLExtension" ...`
>
> Searched the web for `https://github.com/salesforce/ja3`
>
> <details><summary>Explored a file</summary>
>
> - Read `~/.codex/memories_v2/rollout_summaries/2026-11-01T09-34-25-rpMa-ech_strategy_review_and_layer_deployment_clarification.md`
>
> </details>
>
> </details>
</details>

**Studying one controlled TLS profile can explain a mechanism very well. It gives much less evidence that the same fingerprinting method works across the diversity of real applications.** To understand that boundary, we need to separate the application, the TLS code it uses, and the particular handshake that code produces.

Let’s follow one connection, starting close to the bytes.

Suppose a program wants to fetch:

```text
https://shop.example/products
```

There are several distinct jobs involved:

```text
Application / HTTP code
    Decides what to request: /products
             ↓
TLS code
    Establishes a secure channel and protects application bytes
             ↓
Operating system's TCP/IP code
    Delivers an ordered stream of bytes to the other machine
             ↓
Network interface
    Transmits frames over Ethernet, Wi-Fi, etc.
```

This is the usual TLS-over-TCP arrangement. HTTP/3 uses QUIC over UDP and integrates the TLS handshake differently; keep that as a separate branch while learning this one.

The crucial detail is that **the operating system usually does not decide what your TLS ClientHello looks like**. In a typical application, TLS code running inside the application’s process constructs it. The operating system carries those bytes over the network. OpenSSL can either perform socket I/O through its interfaces or let the application move TLS bytes through memory buffers itself. [OpenSSL’s I/O design](https://github.com/openssl/openssl/blob/master/doc/designs/ddd/README.md)

Now consider what that TLS code actually does.

Before sending the protected HTTP request, the client and server need to agree on cryptographic parameters, establish shared secrets, and authenticate the server. In an ordinary full TLS 1.3 handshake using certificates, the broad sequence is:

```text
Client                                      Server

ClientHello ------------------------------->
                         <------------------ ServerHello

                Both can now derive handshake keys

                         <------------------ Encrypted handshake:
                                             server parameters,
                                             certificate,
                                             proof of key possession,
                                             Finished

Encrypted Finished ------------------------>

Protected application data <==============>
```

The server’s certificate binds an identity to a public key through a certificate chain. Its handshake signature proves possession of the corresponding private key. The client checks that evidence, including whether the certificate is valid for the requested hostname. Shared traffic keys are derived through the handshake; the client does not simply send its eventual encryption key in plaintext. Resumption can change this sequence. [TLS 1.3 handshake overview](https://www.rfc-editor.org/rfc/rfc8446.html#section-2)

Notice that the ClientHello comes **before** ordinary handshake encryption. That makes it particularly useful to a passive observer.

The ClientHello is a structured binary message. Conceptually, it contains:

```text
ClientHello
├── Legacy version field
├── Random bytes
├── Legacy session identifier
├── Offered cipher suites
├── Legacy compression field
└── Extensions
    ├── Supported TLS versions
    ├── Supported key-exchange groups
    ├── Key shares
    ├── Supported signature algorithms
    ├── Server name, ordinarily
    ├── Application protocols, such as h2
    └── Other extensions
```

These are encoded as numeric identifiers, lengths, and byte sequences. For example, this is a possible `supported_versions` extension advertising TLS 1.3:

```text
00 2b | 00 03 | 02 | 03 04
  │       │     │      └── TLS 1.3 identifier
  │       │     └───────── Version-list length: 2 bytes
  │       └─────────────── Extension-data length: 3 bytes
  └────────────────────── Extension type: supported_versions
```

The legacy ClientHello version can still say `03 03`, historically TLS 1.2, while this extension advertises TLS 1.3. Reading a field requires understanding its protocol meaning. [TLS message structures and version negotiation](https://www.rfc-editor.org/info/rfc9846/)

Over TCP, the handshake message sits inside TLS records, which have their own headers. **A TLS message, a TLS record, and a TCP packet are different units.** A ClientHello can span records and TCP segments; a segment can contain bytes from multiple records. A packet analyzer must reconstruct the relevant boundaries before interpreting fields.

Now we can distinguish the terminology precisely.

| Term | Meaning | Example |
|---|---|---|
| **TLS protocol** | The agreed rules for messages, cryptography, and state transitions | TLS 1.3 |
| **TLS implementation** | Actual code that carries out those rules | OpenSSL’s TLS code; Go’s `crypto/tls` |
| **TLS library** | Reusable code exposing interfaces applications can call | OpenSSL’s `libssl` |
| **TLS client** | The endpoint playing the client role in a particular TLS connection | A browser establishing HTTPS |
| **TLS server** | The endpoint playing the server role in that connection | A reverse proxy accepting HTTPS |
| **TLS profile**, as used here | A particular selection of TLS behavior and settings | One build, configured versions, algorithms, extensions, and policies |

“Implementation” and “library” overlap substantially. One describes **what the code implements**; the other describes **how applications consume it**.

A TLS library is also more than a collection of encryption functions. Implementing AES alone does not implement TLS. TLS code must serialize messages, parse peer messages, maintain handshake state, derive keys, authenticate transcripts, handle alerts, and enforce protocol rules. Certificate validation and network I/O may involve additional components.

Likewise, **a TLS client is not synonymous with a browser**. A command-line downloader, database connector, email application, mobile app, or backend service can all be TLS clients.

The role belongs to a connection. Consider a reverse proxy:

```text
Browser ─── TLS connection A ───> Reverse proxy
                                     │
                                     └── TLS connection B ───> Backend
```

The proxy is the TLS server on A and the TLS client on B. The connections have separate handshakes and keys. An observer between the proxy and backend sees the proxy’s outgoing TLS behavior.

That also explains why the “server” visible to a browser may be a CDN or load balancer, rather than the machine running the website’s application logic.

There are indeed many TLS implementations in real use. A useful sample is:

| Implementation or family | Where it fits |
|---|---|
| **OpenSSL** | A general-purpose TLS and cryptography toolkit; CPython’s standard `ssl` module uses it |
| **BoringSSL** | Google’s OpenSSL-derived implementation, used by Chrome/Chromium and other software |
| **NSS** | Mozilla’s security libraries, including the TLS implementation used in Firefox’s networking stack |
| **Go `crypto/tls`** | A TLS implementation supplied with Go |
| **rustls** | A TLS implementation written in Rust |
| **Schannel** | Windows’ native TLS security provider |
| **SunJSSE** | A TLS provider supplied with Oracle’s Java implementation, behind Java’s JSSE interfaces |
| **GnuTLS, wolfSSL, Mbed TLS** | Other TLS library families that applications can integrate |

These relationships are documented by [Python](https://docs.python.org/3/library/ssl.html), [BoringSSL](https://github.com/google/boringssl), [Mozilla](https://firefox-source-docs.mozilla.org/networking/sec-necko-components.html), [Go](https://pkg.go.dev/crypto/tls), [rustls](https://rustls.dev/), [Microsoft](https://learn.microsoft.com/en-us/windows/win32/secauthn/secure-channel), [Oracle](https://docs.oracle.com/en/java/javase/25/security/java-secure-socket-extension-jsse-reference-guide.html), and [curl’s backend comparison](https://curl.se/docs/ssl-compared.html).

The two ends **do not need to use the same library**. A BoringSSL client can communicate with an OpenSSL server because they agree on the network protocol. They exchange TLS messages, not library function calls.

Also, an application name does not always tell you its TLS implementation. For example, curl can be built with several different TLS backends. Two installations called “curl” can therefore use different TLS code. [curl’s documentation](https://curl.se/docs/faq.html)

Conversely, two applications using the same library need not send the same ClientHello. The application configures the library: which versions to allow, which application protocols to advertise, whether to resume sessions, and so on. Python’s documentation explicitly distinguishes the wrapper’s chosen defaults from the underlying OpenSSL behavior. [Python’s TLS contexts](https://docs.python.org/3/library/ssl.html#ssl-contexts)

This leads directly to fingerprinting.

**TLS specifies interoperable behavior without prescribing one universal ClientHello.** Implementations and applications can make different choices:

- Which supported options they advertise.
- Their preferences and ordering.
- Which key shares they send immediately.
- Which optional extensions they include.
- How they handle padding, compatibility, and connection state.

A passive observer can use these choices as a recognizable pattern.

A fingerprint such as JA3 selects particular fields rather than hashing every byte. JA3 uses the ClientHello version, cipher-suite list, extension-type list, supported groups, and point formats, with GREASE values excluded as specified by its method. Random bytes and actual key-share bytes are not part of that representation. [JA3’s original description](https://github.com/salesforce/ja3)

Consequently, a fingerprint is a **summary of observable behavior**, not a certificate of software identity.

Two different applications can produce the same selected fields. One application can produce different selected fields across versions or connection states. Even different implementations can deliberately imitate the same ClientHello; uTLS explicitly provides this capability. [uTLS documentation](https://github.com/refraction-networking/utls)

It helps to think of the observed handshake as:

```text
Application's choices
        +
TLS implementation, version, and build
        +
Configuration and feature policies
        +
Connection history and destination information
        +
Randomized behavior
        ↓
Actual ClientHello
        ↓
Fields retained by the fingerprinting method
        ↓
Fingerprint
```

Not every input changes every fingerprint. Changing a hostname, for example, does not directly change standard JA3 through the hostname’s value, because JA3 does not include that value. Changing the extension list can.

Now introduce ECH.

Ordinary TLS protects application data, but its initial ClientHello can expose the intended hostname through **SNI**, Server Name Indication. ECH protects a private **ClientHelloInner** inside a publicly visible **ClientHelloOuter**.

**An ECH-compatible TLS server is a deployment capable of processing ECH in the relevant server role.** In a simple deployment, one endpoint performs ECH decryption and TLS termination. In a split deployment, a client-facing component decrypts the inner hello and forwards it to a cooperating backend. Thus, “the server supports ECH” can describe several coordinated components. [ECH protocol and deployment topologies](https://www.rfc-editor.org/rfc/rfc9849.html#section-3.1)

For an actual connection to use ECH, the client needs a usable ECH configuration containing a public key and metadata, and the deployment needs the corresponding private-key configuration. DNS HTTPS/SVCB records provide a standardized way to distribute this information; a laboratory can supply it directly. [ECH configuration discovery](https://www.rfc-editor.org/rfc/rfc9848.html)

Three separate facts matter:

```text
Server can support ECH
          ≠
Client offers real ECH
          ≠
This connection successfully negotiates ECH
```

An ECH extension can also contain **GREASE ECH**, a dummy offer intended to exercise extension handling. Extension presence alone proves neither a real offer nor acceptance. A passive observer generally cannot verify acceptance from the server’s confirmation without the necessary inner-handshake information. The outer hello remains available for fingerprinting. [ECH client behavior](https://www.rfc-editor.org/rfc/rfc9849.html#section-6)

We can now assess your study’s scope.

By a **controlled TLS profile**, I would mean something like: one application or test harness, one TLS implementation and build, specified configuration, specified transport, and deliberately managed connection state. The experiment then changes a chosen factor—perhaps ECH mode—while controlling other influences.

This can answer a strong, useful question:

> Under these specified conditions, what observable changes accompany the factor we varied?

For example, suppose one client generates absent-ECH, GREASE-ECH, accepted-real-ECH, and rejected-real-ECH cases, with independently verified labels. You can investigate which visible features change, which overlap, and whether a proposed rule works within that environment.

But this does not automatically answer:

> Does that rule distinguish those cases across unrelated real-world clients?

Imagine a hypothetical result:

```text
Laboratory:
  Real-ECH cases   → larger visible hello
  GREASE cases     → smaller visible hello

Another client:
  Uses different padding for GREASE
                  → similarly large visible hello
```

The original observation could be correct. Its interpretation as a general discriminator would still fail. The rule may have learned a client’s padding policy.

The same problem arises if all real-ECH samples come from client A and all GREASE samples come from client B. A classifier can achieve excellent accuracy by identifying A versus B, without learning a reliable distinction between real ECH and GREASE.

**The size of the limitation depends on what you claim to fingerprint.**

| Intended claim | What one controlled profile contributes |
|---|---|
| “Our parser extracts these fields correctly” | Useful evidence, supplemented by diverse message and boundary cases |
| “Changing ECH mode affects these features in this setup” | Strong evidence when controls and labels are sound |
| “This feature distinguishes ECH states across clients” | Initial evidence requiring independent-client evaluation |
| “This fingerprint identifies a specific application” | Limited evidence without overlap, version, and mimicry analysis |
| “This method works across Internet traffic” | Insufficient evidence on its own |

There is no defensible percentage for “how much scope we lose” simply from the number of libraries tested. Real traffic is unevenly distributed, and application count, implementation diversity, and deployment diversity measure different things.

A hundred programs sharing nearly identical TLS behavior may provide less new coverage than a few deliberately different stacks. BoringSSL is also derived from OpenSSL, so distinct library names do not necessarily mean independent ancestry.

A practical progression would be:

1. **Establish the mechanism within one profile.** Repeat connections, retain natural randomness, and label outcomes independently.
2. **Vary settings and state within that implementation.** Check whether the result depends on resumption, advertised protocols, padding, or other choices.
3. **Evaluate a separate implementation.** For ECH-specific tests, first establish that its particular build supports the required behavior.
4. **Evaluate a client excluded from rule development.** Keep whole clients or implementation families out of training, rather than merely withholding random connections from the same profile.
5. **Broaden servers and deployment conditions when making broader claims.** Server responses reflect both the client’s offer and server policy.

Ten thousand repeated connections are valuable for measuring variability within a profile. They do not become ten thousand independent tests of client diversity.

My assessment is that **a controlled-profile study is a defensible first stage, especially for understanding ECH mechanisms and testing a passive analyzer. Its main limitation is generalization.** You can show what happens under specified conditions; claiming reliable client identification or ECH-state discrimination across the wider ecosystem requires additional evidence.

As a check on the distinction: if two differently named applications use the same TLS library with the same settings, what additional evidence would make you confident that testing both meaningfully broadened your study?
