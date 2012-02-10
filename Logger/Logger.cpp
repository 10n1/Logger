#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include "WebSocketServer.h"

#pragma comment( lib, "Ws2_32.lib" )

static const char* szTestKeys[] = {
    "sc5ylxhGSPjKqVujEKmtzg==", "Vx1V8T6Anm7qhoJ79g648tBx18k=",
    "V7jh2EKK9SGDfNDDpXnuqQ==", "QE+JxXP3Jr55j2Zz0Mr37K1rtr8=",
};

int main( void )
{
    WebSocketServer wsServer;

    wsServer.Start();
    wsServer.Stop();

    return 0;
}
