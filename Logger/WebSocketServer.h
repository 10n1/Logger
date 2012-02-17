// WebSocketServer.h

#ifndef _WEBSOCKET_SERVER_H_
#define _WEBSOCKET_SERVER_H_

class WebSocketServer
{
public:
    WebSocketServer( void );
    WebSocketServer( const char* szHost, unsigned int nPort );
    ~WebSocketServer( void );

    void Start( void );
    void Stop( void );
    bool OpenSocket( void );

    unsigned int RetrieveWebSocketKey( const char* szRequestHeader, char* szWebSocketKey );
    unsigned int PrepareResponse( const char* szWebSocketKey, char* szResponseHeader );

    void SendMessge( const char* szServerMessage );

private:
    unsigned int SHA1( const unsigned char* szMessage, char* szMessageHash );
    unsigned int Base64Encode( const unsigned char* szMessage, char* szEncodedMessage );

    WSAData m_wsaData;
    // used to open up a port on the server to listen for clients' requests
    SOCKET m_ServerSocket;
    // used to communicate with clients
    SOCKET m_ClientListener;

    struct addrinfo* m_addrResult;
    struct addrinfo m_addrHints;

    const char* m_szHost;
    unsigned int m_nPort;

};

#endif // _WEBSOCKET_SERVER_H_
