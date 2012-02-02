#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>

extern "C" {
#include "sha1.h"
}
#include "Base64Encoder.h"

#pragma comment( lib, "Ws2_32.lib" )

enum eResponseHeader
{
    URI = 0,
    Upgrade,
    Connection,
    WebsocketAccept
};
static const char* szResponseHeaderStrings[] = {
    "HTTP/1.1 101 Switching Protocols\r\n",
    "Upgrade: websocket\r\n",
    "Connection: Upgrade\r\n",
    "Sec-WebSocket-Accept: ",
};

static const unsigned int SERVER_PORT = 12345;
static const char* WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void SHA1( const unsigned char* szMessage, char* szDigestMessage )
{
    SHA1Context shaContext;

    // clear SHA context
    SHA1Reset( &shaContext );

    // pass in the message
    SHA1Input( &shaContext, szMessage, strlen( (const char*)szMessage ) );

    // get result
    SHA1Result( &shaContext );

    // merge digest
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
        szDigestMessage[ ii / 2 ] = j;
    }
    szDigestMessage[ ii / 2 ] = 0;
}

void ParseRequest( const char* szRequest, char** szResponse, unsigned int* nResponseSize )
{
    aoBase64Encoder Base64Encoder;
    char szRaw[ MAX_PATH ];
    char szRawRequest[ MAX_PATH ];
    char szWebsocketKey[ MAX_PATH ];

    // parse request
    sprintf( szRawRequest, "%s", szRequest);
    sprintf( szRaw, "%s", strtok( szRawRequest, "\r\n" ) );  // URI
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Upgrade
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Connection
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Host
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Origin
    sprintf( szWebsocketKey, "%s", strtok( NULL, "\r\n" ) ); // Sec-WebSocket-Key
    sprintf( szRaw, "%s", strtok( NULL, "\r\n" ) );          // Sec-WebSocket-Version
    sprintf( szWebsocketKey, "%s", strtok( szWebsocketKey, " " ) );
    sprintf( szWebsocketKey, "%s", strtok( NULL, " " ) );

    // create response
    char szAcceptKey[ MAX_PATH ];
    char szAcceptKeySHA1[ MAX_PATH ];
    char szAcceptKeyBase64[ MAX_PATH ];
    char* a = NULL;
    a = szAcceptKey;

    // concatenate Sec-WebSocket-Key with Special WebSocket GUID
    strcpy( a, szWebsocketKey );
    a += strlen( szWebsocketKey );

    strcpy( a, WEBSOCKET_GUID );
    a += strlen( WEBSOCKET_GUID );

    // SHA1 hash
    SHA1( ( const unsigned char* )szAcceptKey, szAcceptKeySHA1 );
    int nSHA1Size = strlen( szAcceptKeySHA1 );

    // Base64 encode the SHA1 hash
    Base64Encoder.Encode( (const unsigned char*)szAcceptKeySHA1, nSHA1Size );
    sprintf( szAcceptKeyBase64, "%s\0", Base64Encoder.GetEncoded() );

    // create response string
    size_t nResponseMallocSize = 256 * 2;
    *szResponse = ( char* )malloc( nResponseMallocSize );
    char* p = NULL;
    p = *szResponse;

    strcpy( p, szResponseHeaderStrings[ eResponseHeader::URI ] );
    p += strlen( szResponseHeaderStrings[ eResponseHeader::URI ] );

    strcpy( p, szResponseHeaderStrings[ eResponseHeader::Upgrade ] );
    p += strlen( szResponseHeaderStrings[ eResponseHeader::Upgrade ] );

    strcpy( p, szResponseHeaderStrings[ eResponseHeader::Connection ] );
    p += strlen( szResponseHeaderStrings[ eResponseHeader::Connection ] );

    strcpy( p, szResponseHeaderStrings[ eResponseHeader::WebsocketAccept ] );
    p += strlen( szResponseHeaderStrings[ eResponseHeader::WebsocketAccept ] );
    strcpy( p, szAcceptKeyBase64 );
    p += strlen( szAcceptKeyBase64 );

    strcpy( p, "\r\n\r\n" );
    p += strlen( "\r\n\r\n" );

    // response string size
    *nResponseSize = p - *szResponse;
}


#define DEFAULT_PORT "12345"
#define DEFAULT_BUFLEN 512

int main( void )
{
    WSADATA wsaData;

    int iResult = WSAStartup( MAKEWORD( 2, 2 ), &wsaData );
    if( iResult != 0 )
    {
        printf( "WSAStartup failed %d\n", iResult );
        return 1;
    }

    struct addrinfo* result = NULL;
    struct addrinfo* ptr = NULL;
    struct addrinfo hints;

    ZeroMemory( &hints, sizeof( hints ) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo( NULL, DEFAULT_PORT, &hints, &result );
    if( iResult != 0 )
    {
        printf( "getaddrinfo failed: %d\n", iResult );
        WSACleanup();
        return 1;
    }

    // create listen socket
    SOCKET ConnectionSocket = INVALID_SOCKET;

    ConnectionSocket = socket( result->ai_family, result->ai_socktype, result->ai_protocol );
    if( ConnectionSocket == INVALID_SOCKET )
    {
        printf( "Error at socket(): %ld\n", WSAGetLastError() );
        freeaddrinfo( result );
        WSACleanup();
        return 1;
    }

    // bind listen socket
    iResult = bind( ConnectionSocket, result->ai_addr, (int)result->ai_addrlen );
    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket( ConnectionSocket );
        WSACleanup();
        return 1;
    }

    freeaddrinfo( result );

    // listen for connection
    if( listen( ConnectionSocket, SOMAXCONN ) == SOCKET_ERROR )
    {
        printf( "Listen failed with error: %ld\n", WSAGetLastError() );
        closesocket( ConnectionSocket );
        WSACleanup();
        return 1;
    }

    // accept client connection
    SOCKET RecvSendSocket = INVALID_SOCKET;

    RecvSendSocket = accept( ConnectionSocket, NULL, NULL );
    if( RecvSendSocket == INVALID_SOCKET )
    {
        printf( "accept failed: %ld\n", WSAGetLastError() );
        closesocket( ConnectionSocket );
        WSACleanup();
        return 1;
    }

    // close listen socket
    closesocket( ConnectionSocket );
        
    // receive / send data
    char recvbuf[ DEFAULT_BUFLEN ];
    int recvbuflen = DEFAULT_BUFLEN;
    int iReceivedBytes, iSentBytes;

    // response data
    char* szHandshakeResponse = NULL;
    unsigned int nHandshakeSize = 0;

    do
    {
        // handshake part 1
        iReceivedBytes = recv( RecvSendSocket, recvbuf, recvbuflen, 0 );
        if( iReceivedBytes > 0 )
        {
            // prepare response header
            ParseRequest( recvbuf, &szHandshakeResponse, &nHandshakeSize );

            printf( "bytes received: %d\n", iReceivedBytes );
            printf( "------------------\n" );
            printf( "%s\n\n", recvbuf );

            // handshake part 2
            iSentBytes = send( RecvSendSocket, szHandshakeResponse, nHandshakeSize, 0 );
            if( iSentBytes == SOCKET_ERROR )
            {
                printf( "send failed: %ld\n", WSAGetLastError() );
                closesocket( RecvSendSocket );
                WSACleanup();
                return 1;
            }

            printf( "bytes sent: %d\n", iSentBytes );
            printf( "------------------\n" );
            printf( "%s\n\n", szHandshakeResponse );
        }
        else if( iReceivedBytes == 0 )
        {
            printf( "connection closing...\n" );
        }
        else
        {
            printf( "recv failed: %ld\n", WSAGetLastError() );
            closesocket( RecvSendSocket );
            WSACleanup();
            return 1;
        }
    } while( iReceivedBytes > 0 );

    // shutdown socket
    iResult = shutdown( RecvSendSocket, SD_SEND );
    if( iResult == SOCKET_ERROR )
    {
        printf( "shutdown failed: %ld\n", WSAGetLastError() );
        closesocket( RecvSendSocket );
        WSACleanup();
        return 1;
    }

    closesocket( RecvSendSocket );
    WSACleanup();

    return 0;
}
