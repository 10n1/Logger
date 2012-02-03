// WebSocketServer.cpp

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include "WebSocketServer.h"
#include "Base64Encoder.h"

extern "C" { 
#include "sha1.h" 
}

static const char* LOCALHOST = "127.0.0.1";
static const unsigned int DEFAULT_PORT = 12345;
static const unsigned int RECEIVE_BUFFER_SIZE = 512;

WebSocketServer::WebSocketServer( void )
    : m_szHost( LOCALHOST )
    , m_nPort( DEFAULT_PORT )
    , m_ServerSocket( INVALID_SOCKET )
    , m_ClientSocket( INVALID_SOCKET )
{
}

WebSocketServer::WebSocketServer( const char* szHost, unsigned int nPort )
    : m_szHost( szHost )
    , m_nPort( nPort )
    , m_ServerSocket( INVALID_SOCKET )
    , m_ClientSocket( INVALID_SOCKET )
{
}

WebSocketServer::~WebSocketServer( void )
{
    Stop();
}

void WebSocketServer::Start( void )
{
    // open server socket to listen for client connections
    OpenSocket();

    // accept incoming connections
    m_ClientSocket = accept( m_ServerSocket, NULL, NULL );
    if( m_ClientSocket == INVALID_SOCKET )
    {
        printf( "accept for m_ClientSocket failed :(\n" );
        closesocket( m_ServerSocket );
        WSACleanup();
        // crash!
    }

    char szReceiveBuffer[ RECEIVE_BUFFER_SIZE ];
    unsigned int nReceiveBufferSize = RECEIVE_BUFFER_SIZE;

    char szWebSocketKey[ MAX_PATH ];
    char szResponseHeader[ MAX_PATH ];

    // execute initial handshake
    int iReceivedBytes = recv( m_ClientSocket, szReceiveBuffer, nReceiveBufferSize, 0 );
    if( iReceivedBytes > 0 )
    {
        RetrieveWebSocketKey( szReceiveBuffer, szWebSocketKey );
        PrepareResponse( szWebSocketKey, szResponseHeader );

        int iSentBytes = send( m_ClientSocket, szResponseHeader, strlen( szResponseHeader ), 0 );
        if( iSentBytes == SOCKET_ERROR )
        {
            printf( "send failed :(\n" );
            closesocket( m_ClientSocket );
            WSACleanup();
            // crash!
        }
    }
    else
    {
        printf( "recv failed :(\n" );
        closesocket( m_ClientSocket );
        WSACleanup();
        // crash!
    }

    // ??
}

void WebSocketServer::Stop( void )
{
    shutdown( m_ClientSocket, SD_SEND );
    closesocket( m_ServerSocket );
    closesocket( m_ClientSocket );
    WSACleanup();
    m_ServerSocket = INVALID_SOCKET;
    m_ClientSocket = INVALID_SOCKET;
}

bool WebSocketServer::OpenSocket( void )
{
    bool bInitialized = true;

    int iResult = WSAStartup( MAKEWORD( 2, 2 ), &m_wsaData );
    if( iResult != 0 )
    {
        printf( "WSAStartup failed :(\n" );
        bInitialized = false;
        // crash!
    }

    ZeroMemory( &m_addrHints, sizeof( struct addrinfo ) );
    m_addrHints.ai_family = AF_INET;
    m_addrHints.ai_socktype = SOCK_STREAM;
    m_addrHints.ai_protocol = IPPROTO_TCP;
    m_addrHints.ai_flags = AI_PASSIVE;

    char szPort[ MAX_PATH ];
    sprintf( szPort, "%d", m_nPort );

    iResult = getaddrinfo( NULL, szPort, &m_addrHints, &m_addrResult );
    if( iResult != 0 )
    {
        printf( "getaddrinfo failed :(\n" );
        WSACleanup();
        bInitialized = false;
        // crash!
    }

    m_ServerSocket = socket( m_addrResult->ai_family, m_addrResult->ai_socktype, m_addrResult->ai_protocol );
    if( m_ServerSocket == INVALID_SOCKET )
    {
        printf( "socket creation for m_ServerSocket failed :(\n" );
        freeaddrinfo( m_addrResult );
        WSACleanup();
        bInitialized = false;
        // crash!
    }

    // bind socket to host:port
    if( bind( m_ServerSocket, m_addrResult->ai_addr, ( int )m_addrResult->ai_addrlen ) == SOCKET_ERROR )
    {
        printf( "bind for m_ServerSocket failed :(\n" );
        freeaddrinfo( m_addrResult );
        closesocket( m_ServerSocket );
        WSACleanup();
        bInitialized = false;
        // crash!
    }

    freeaddrinfo( m_addrResult );

    // begin listening for connections
    if( listen( m_ServerSocket, SOMAXCONN ) == SOCKET_ERROR )
    {
        printf( "listen for m_ServerSocket failed :(\n" );
        closesocket( m_ServerSocket );
        WSACleanup();
        bInitialized = false;
        // crash!
    }

    return bInitialized;
}

unsigned int WebSocketServer::RetrieveWebSocketKey(  const char* szRequestHeader, char* szWebSocketKey )
{
    char szRaw[ MAX_PATH ];
    char szRawRequest[ MAX_PATH ];

    // extract the WebSocket Key
    sprintf( szRawRequest, "%s", szRequestHeader );
    sprintf( szRaw, "%s", strtok( szRawRequest, "\r\n" ) );  // URI
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Upgrade
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Connection
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Host
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Origin
    sprintf( szWebSocketKey, "%s", strtok( NULL, "\r\n" ) ); // Sec-WebSocket-Key
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Sec-WebSocket-Version
    sprintf( szWebSocketKey, "%s", strtok( szWebSocketKey, " " ) );
    sprintf( szWebSocketKey, "%s", strtok( NULL, " " ) );

    return strlen( szWebSocketKey );
}

unsigned int WebSocketServer::PrepareResponse( const char* szWebSocketKey, char* szResponseHeader )
{
    static const char* szWebSocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char szWebSocketKey_GUID[ MAX_PATH ];
    char szSHA1Hash[ MAX_PATH ];
    char szBase64[ MAX_PATH ];
    char* p = NULL;

    // concatenate WebSocket Key with the GUID
    sprintf( szWebSocketKey_GUID, "%s%s", szWebSocketKey, szWebSocketGUID );

    // generate SHA1 hash of the Key_GUID
    unsigned int nHashSize = SHA1( ( unsigned char* )szWebSocketKey_GUID, szSHA1Hash );

    // base64 encode the SHA1 hash of the Key_GUID
    unsigned int nBase64Size = Base64Encode( ( unsigned char* )szSHA1Hash, szBase64 );

    // create response header
    p = szResponseHeader;

    strcpy( p, "HTTP/1.1 101 Switching Protocols\r\n" );
    p += strlen( "HTTP/1.1 101 Switching Protocols\r\n" );

    strcpy( p, "Upgrade: websocket\r\n" );
    p += strlen( "Upgrade: websocket\r\n" );

    strcpy( p, "Connection: Upgrade\r\n" );
    p += strlen( "Connection: Upgrade\r\n" );

    strcpy( p, "Sec-WebSocket-Accept: " );
    p += strlen( "Sec-WebSocket-Accept: " );

    strcpy( p, szBase64 );
    p += strlen( szBase64 );

    strcpy( p, "\r\n\r\n" );
    p += strlen( "\r\n\r\n" );

    return ( unsigned int )( p - szResponseHeader );
}

unsigned int WebSocketServer::SHA1( const unsigned char* szMessage, char* szMessageHash )
{
    SHA1Context shaContext;

    SHA1Reset( &shaContext );
    SHA1Input( &shaContext, szMessage, strlen( ( const char* )szMessage ) );
    SHA1Result( &shaContext );

    char szDigest[ MAX_PATH ];
    sprintf( szDigest, "%x%x%x%x%x", shaContext.Message_Digest[0], shaContext.Message_Digest[1],
        shaContext.Message_Digest[2], shaContext.Message_Digest[3], shaContext.Message_Digest[4] );

    unsigned int ii = 0;
    unsigned int nDigestLength = strlen( szDigest );
    for( ii = 0; ii < nDigestLength; ii += 2)
    {
        char substring[] = { szDigest[ ii ], szDigest[ ii + 1 ], 0 };
        int j = 0;
        sscanf_s( substring, "%x", &j );
        szMessageHash[ ii / 2 ] = j;
    }
    szMessageHash[ ii / 2 ] = 0;

    return ( unsigned int )strlen( szMessageHash );
}

unsigned int WebSocketServer::Base64Encode( const unsigned char* szMessage, char* szEncodedMessage )
{
    aoBase64Encoder b64Encoder;

    b64Encoder.Encode( szMessage, strlen( ( const char* )szMessage ) );
    sprintf( szEncodedMessage, "%s", b64Encoder.GetEncoded() );

    return ( unsigned int )strlen( szEncodedMessage );
}
