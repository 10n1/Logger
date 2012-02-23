// WebSocketServer.cpp

// TODO: cross-platform sockets
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include "WebSocketServer.h"
#include "modp_b64.h"
#include "modp_b64_data.h"

extern "C" { 
#include "sha1.h" 
}

// NOTE: sending/receiving messages follows the following packet format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+

//enum WSMessage_Type
//{
//    Handshake = 0,
//    Packet,
//    Count,
//};
//
//typedef struct _WSMessage
//{
//    unsigned int nSender;
//    unsigned int nType;
//    char* szData;
//} WSMessage;


static const char* LOCALHOST = "127.0.0.1";
static const unsigned int DEFAULT_PORT = 12345;
static const unsigned int RECEIVE_BUFFER_SIZE = 512;

WebSocketServer::WebSocketServer( void )
    : m_szHost( LOCALHOST )
    , m_nPort( DEFAULT_PORT )
    , m_ServerSocket( INVALID_SOCKET )
    , m_ClientListener( INVALID_SOCKET )
{
}

WebSocketServer::WebSocketServer( const char* szHost, unsigned int nPort )
    : m_szHost( szHost )
    , m_nPort( nPort )
    , m_ServerSocket( INVALID_SOCKET )
    , m_ClientListener( INVALID_SOCKET )
{
}

WebSocketServer::~WebSocketServer( void )
{
    Stop();
}

void WebSocketServer::Start( void )
{
    bool bSocketOpen = false; 
    bool bListening = false;
    int iReceivedBytes = 0;
    int iSentBytes = 0;
    char szReceiveBuffer[ RECEIVE_BUFFER_SIZE ];
    unsigned int nReceiveBufferSize = RECEIVE_BUFFER_SIZE;
    char szWebSocketKey[ MAX_PATH ];
    char szResponseHeader[ MAX_PATH ];
    bool bHandshakeSuccessful = false;


    bSocketOpen = OpenSocket();

    while( bSocketOpen )
    {
        m_ClientListener = accept( m_ServerSocket, NULL, NULL );
        if( m_ClientListener == INVALID_SOCKET )
        {
            bSocketOpen = false;
            printf( "accept for m_ClientListener failed :(\n" );
            closesocket( m_ServerSocket );
            WSACleanup();
        }

        bListening = true;

        while( bListening )
        {

            iReceivedBytes = recv( m_ClientListener, szReceiveBuffer, nReceiveBufferSize, 0 );

            // process messages from webpage
            if( iReceivedBytes > 0 )
            {
                printf( "# bytes received: %d\n%s\n", iReceivedBytes, szReceiveBuffer );

                // the webpage will continue to attempt a connection until it succeeds
                // so we have to check whether the message received is either:
                //   a. connection attempt (websocket handshake)
                //   b. regular/command message
                char szRequestType[] = { szReceiveBuffer[0], szReceiveBuffer[1], szReceiveBuffer[2], 0 };
                // if the first 3 characters of the request string are "GET"
                // then:
                //   this message is a connection attempt so the handshake needs to happen
                // else:
                //   this is a regular message and a successful connection exists
                bHandshakeSuccessful = ( strcmp( "GET", szRequestType ) == 0 ) ? false : true;

                // 1) process initial websocket handshake
                if( !bHandshakeSuccessful )
                {
                    printf( "Processing websocket handshake...\n" );

                    unsigned int nWebSocketKeyLength = RetrieveWebSocketKey( szReceiveBuffer, szWebSocketKey );
                    unsigned int nResponseLength = PrepareResponse( szWebSocketKey, szResponseHeader );

                    if( nResponseLength == 0 )
                    {
                        printf( "invalid response length :(\n" );
                        break;
                    }

                    iSentBytes = send( m_ClientListener, szResponseHeader, nResponseLength, 0 );
                    if( iSentBytes == SOCKET_ERROR )
                    {
                        bListening = false;
                        printf( "send failed :(\n" );
                        //closesocket( m_ClientListener );
                        //WSACleanup();
                        break;
                    }
                }
                // 2) process regular messages
                else
                {
                    printf( "Processing message from webpage logger...\n" );

                    // TODO: parse out the commands sent from the webpage
                    printf( "message from webpage: %x\n", szReceiveBuffer );
                }
            }
            else
            {
                bListening = false;
                printf( "recv failed :( \n" );
                //closesocket( m_ClientListener );
                //WSACleanup();
                break;
            }
        }
    }

    CloseSocket();

    // ??
}

unsigned int WebSocketServer::ProcessHandshake( void )
{
    return 0;
}

void WebSocketServer::Stop( void )
{
    shutdown( m_ClientListener, SD_SEND );
    closesocket( m_ServerSocket );
    closesocket( m_ClientListener );
    WSACleanup();
    m_ServerSocket = INVALID_SOCKET;
    m_ClientListener = INVALID_SOCKET;
}

bool WebSocketServer::OpenSocket( void )
{
    bool bInitialized = true;

    int iResult = WSAStartup( MAKEWORD( 2, 2 ), &m_wsaData );
    if( iResult != 0 )
    {
        printf( "WSAStartup failed :(\n" );
        bInitialized = false;
        DebugBreak(); // crash!
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
        DebugBreak(); // crash!
    }

    m_ServerSocket = socket( m_addrResult->ai_family, m_addrResult->ai_socktype, m_addrResult->ai_protocol );
    if( m_ServerSocket == INVALID_SOCKET )
    {
        printf( "socket creation for m_ServerSocket failed :(\n" );
        freeaddrinfo( m_addrResult );
        WSACleanup();
        bInitialized = false;
        DebugBreak(); // crash!
    }

    // bind socket to host:port
    if( bind( m_ServerSocket, m_addrResult->ai_addr, ( int )m_addrResult->ai_addrlen ) == SOCKET_ERROR )
    {
        printf( "bind for m_ServerSocket failed :(\n" );
        freeaddrinfo( m_addrResult );
        closesocket( m_ServerSocket );
        WSACleanup();
        bInitialized = false;
        DebugBreak(); // crash!
    }

    freeaddrinfo( m_addrResult );

    // begin listening for connections
    if( listen( m_ServerSocket, SOMAXCONN ) == SOCKET_ERROR )
    {
        printf( "listen for m_ServerSocket failed :(\n" );
        closesocket( m_ServerSocket );
        WSACleanup();
        bInitialized = false;
        DebugBreak(); // crash!
    }

    return bInitialized;
}

// note: only closes server socket
bool WebSocketServer::CloseSocket( void )
{
    closesocket( m_ServerSocket );
    WSACleanup();

    return true;
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

    return ( unsigned int )( strlen( szWebSocketKey ) );
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
    if( nHashSize == 0 )
        return 0;

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

void WebSocketServer::SendMessge( const char* szServerMessage )
{
}

// Util handshake functions
unsigned int WebSocketServer::SHA1( const unsigned char* szMessage, char* szMessageHash )
{
    static SHA1Context shaContext;

    SHA1Reset( &shaContext );
    SHA1Input( &shaContext, szMessage, strlen( ( const char* )szMessage ) );
    SHA1Result( &shaContext );

    char szDigest[ MAX_PATH ];
    unsigned int nHashLength = 0;
    if( shaContext.Computed && !shaContext.Corrupted )
    {
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

        nHashLength = ( unsigned int )strlen( szMessageHash );
    }

    return nHashLength;
}

unsigned int WebSocketServer::Base64Encode( const unsigned char* szMessage, char* szEncodedMessage )
{
    char szSrcMessage[ MAX_PATH ];
    sprintf( szSrcMessage, "%s", szMessage );

    modp_b64_encode( szEncodedMessage, szSrcMessage, strlen( szSrcMessage ) );

    return ( unsigned int )strlen( szEncodedMessage );
}
