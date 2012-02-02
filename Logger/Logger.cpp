#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include "WebSocketServer.h"

#pragma comment( lib, "Ws2_32.lib" )


int main( void )
{
    WebSocketServer wsServer;
    
    wsServer.Start();
    wsServer.Stop();

    return 0;
}
