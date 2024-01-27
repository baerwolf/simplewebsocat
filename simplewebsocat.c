/* simplewebsocat.c
 * version 20240127Z1245SB
 * 
 * an TCP-Server forwarding connections to websockets
 * (using libcurl)
 * 
 * WARNING
 * In debian 11 (bullseye) there is no libcurl-dev supporting websockets !!
 * You have to compile libcurl yourself (activating websockets) and link
 * this tool against the new version.
 * 
 * You can do this for example:
 * mkdir -p /tmp/delme.${USER}/libcurl
 * cd /tmp/delme.${USER}/
 * git clone https://github.com/curl/curl
 * cd curl
 * git tag -v curl-8_5_0
 * git reset --hard curl-8_5_0
 * #in case you want your own libssl, too: #export PKG_CONFIG_PATH="/tmp/delme.${USER}/libcurl/lib/pkgconfig:${PKG_CONFIG_PATH}"
 * ./buildconf 
 * ./configure --prefix="/tmp/delme.${USER}/libcurl/" --enable-websockets --enable-http-auth --with-openssl
 * #[...]
 * #WARNING:  Websockets enabled but marked EXPERIMENTAL. Use with caution!
 * time make
 * time make install
 * 
 * by Stephan Bärwolf, Rudolstadt 2024
 */

#define MYVERSION "20240127Z1245SB"
#define HANDLE_WSPING 0

/* 
 * 
 * gcc -DDEBUG=10 -O2 -o simplewebsocat simplewebsocat.c -I/tmp/delme.${USER}/libcurl/include -L/tmp/delme.${USER}/libcurl/lib -lpthread -lcrypto -lssl -lcurl
 * patchelf --set-rpath /tmp/delme.${USER}/libcurl/lib simplewebsocat
 * 
 * --== OR run: ==--
 * LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:/tmp/delme.${USER}/libcurl/lib" ./simplewebsocat
 * 
 * 
 * --== OR build static: ==--
 * export PKG_CONFIG_PATH="/tmp/delme.${USER}/libcurl/lib/pkgconfig:${PKG_CONFIG_PATH}"
 * gcc -DDEBUG=10 -O2 -o simplewebsocat simplewebsocat.c $(pkg-config --static --cflags libcurl) /tmp/delme.${USER}/libcurl/lib/libcurl.a  $(pkg-config --static --libs libcurl | sed 's/-lcurl//') $(pkg-config --static --libs-only-other libcurl) 
 * #patchelf --set-rpath /tmp/delme.${USER}/libcurl/lib simplewebsocat
 * 
 */

/*
 * pub   rsa2048 2016-04-07 [SC]
 *      27EDEAF22F3ABCEB50DB9A125CC908FDB71E12C2
 * uid        [ unbekannt ] Daniel Stenberg <daniel@haxx.se>
 * sub   rsa2048 2016-04-07 [E]


-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Hostname: 
Version: Hockeypuck 2.1.1-10-gec3b0e7

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
t6Jm6IXV9cry8i6x
=n85h
-----END PGP PUBLIC KEY BLOCK-----
*/

#define _GNU_SOURCE

#ifndef MYMAXCONNECTIONS
#   define MYMAXCONNECTIONS (16)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdatomic.h>
#include <signal.h>
#include <assert.h>

#include <netinet/tcp.h>
#include <curl/curl.h>

#define INVALID_SOCKET (-1)
#define ISVALIDSOCKET(s) ((s) >= 0)
#define ISSELECTSOCKET(s) (((s) >= 0) && (s < FD_SETSIZE)) /* I want every fd usable for select */
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#define GETSOCKETERRNO() (errno)


#define assigned(x) ((x)!=NULL)
#define myOK(x)      ((x)==EXIT_SUCCESS)
#define FREE(x) {free(x); x=NULL;}

#define DBGSTREAM	stderr
#if (DEBUG>0)
#define DBGPRINTF(level, args...) { if ((DEBUG) >= (level)) fprintf(DBGSTREAM, ##args); }
#define DBGOUT(level, args...)  {DBGPRINTF(level,"%s:%i (%s, pid=%i):\t",__FILE__,__LINE__,__FUNCTION__,(int)getpid()); DBGPRINTF(level,##args); }
#else
#define DBGPRINTF(level, args...)
#define DBGOUT(level, args...)
#endif

#define ERROUT(level)		{int _tmp=errno; DBGOUT(level,"%s (%i)\n", strerror(_tmp), _tmp); }

#define DBGERROR              1
#define DBGWARN               2
#define DBGINFO               7
#define DBGCHILD              8
#define DBGANNOUNCE           9


//////////////////////////////////////////////////////////////////////////////
static volatile atomic_bool doExit = false;
void exithandler(int sig, siginfo_t *info, void *ucontext) {
    //this thing has its own stack - be careful...
    atomic_store(&doExit, true);
}
int install_handlers(void) {
    int result = EXIT_SUCCESS;
    struct sigaction sig;

    memset(&sig, 0, sizeof(sig));
    sig.sa_sigaction=exithandler;
    sig.sa_flags=0;
    sigemptyset(&sig.sa_mask);
    sigaddset(&sig.sa_mask, SA_ONSTACK);
    sigaddset(&sig.sa_mask, SA_SIGINFO);

    if (sigaction(SIGINT, &sig, NULL) == -1) { atomic_store(&doExit, true); result=EXIT_FAILURE; }
    if (sigaction(SIGHUP, &sig, NULL) == -1) { atomic_store(&doExit, true); result=EXIT_FAILURE; }

    return result;
}

//////////////////////////////////////////////////////////////////////////////
#define myapplicationconfig_temps (3)
struct myapplicationconfig {
    bool verbosedump;

    char *bindaddress;
    char *bindport;
    
    char *proxyurl; //for example: "https://user:password@orgproxy.mydns.zone:3128"
    char *proxyCApath;
    
    char *wsurl;
    char *CApath;
    bool verifypeer;
    bool verifyproxy;
    bool verbose;
    
    uint8_t timout_sec;
    unsigned int wsKeepAlive_msec;
    
    char *tmp[myapplicationconfig_temps];
};

int setDefaultConfig(struct myapplicationconfig *cfg) {
    int i, result=EXIT_SUCCESS;

    cfg->verbosedump=false;

    cfg->bindaddress=strdup("127.0.0.1");
    if (!assigned(cfg->bindaddress)) result=EXIT_FAILURE;

    cfg->bindport=strdup("41024");
    if (!assigned(cfg->bindport)) result=EXIT_FAILURE;

    cfg->proxyurl=NULL;
    cfg->proxyCApath=NULL;
    cfg->verifypeer=true;
    cfg->verifyproxy=true;
    cfg->verbose=false;
    cfg->timout_sec=15;
    cfg->wsKeepAlive_msec=0; //no keepalive

    cfg->wsurl=strdup("wss://localhost:8443/websockify");
    cfg->CApath=NULL;
   // cfg->wsurl=strdup("ws://10.128.0.152:8080/localhost:22");cfg->verifypeer=false; cfg->verbose=false;
    //ECDSA key fingerprint is SHA256:o5HkCt397FNCc886PVorOHUEsPDeSg1M+VbF7EUPbhU.
    //cfg->proxyurl=strdup("http://10.19.241.33:3128/"); //cfg->verifyproxy=false;
    //cfg->wsurl=strdup("wss://secureuser:pass4secureuser@87.181.178.1/localhost:22"); cfg->verifypeer=false; cfg->verbose=fal; cfg->wsKeepAlive_msec=30000; cfg->timout_sec=15;
    if (!assigned(cfg->wsurl)) result=EXIT_FAILURE;
    
    for (i=0;i<myapplicationconfig_temps;i++) cfg->tmp[i]=NULL;
    return result;
}

void printConfig(FILE *stream, struct myapplicationconfig *c) {
    int i;

    fprintf(stream, "\tverbosedump      = %s, verbose(curl) = %s\n", (c->verbosedump)?"true":"false", (c->verbose)?"true":"false");
    fprintf(stream, "\tbindaddress      = %s:%s(=bindport)\n", c->bindaddress, c->bindport);
    
    if (c->proxyurl) {
        fprintf(stream, "\tproxyurl         = %s\t(%s)\n", c->proxyurl, (c->verifyproxy)?"will verify":"UNVERIFIED");
        fprintf(stream, "\tproxyCAPath      = %s\n", assigned(c->proxyCApath)?c->proxyCApath:"using system default");
    }

    fprintf(stream, "\twsurl            = %s\t(%s)\n", c->wsurl, (c->verifypeer)?"will verify":"UNVERIFIED");
    fprintf(stream, "\tCAPath           = %s\n", assigned(c->CApath)?c->CApath:"using system default");
    fprintf(stream, "\twsKeepAlive_msec = %d\t%s\n", c->wsKeepAlive_msec, (c->wsKeepAlive_msec==0)?"(ping switched off)":"");
    fprintf(stream, "\ttimout_sec       = %d\t(the select timeout - basically polling interval)\n", c->timout_sec);
    
    for (i=0;i<myapplicationconfig_temps;i++) {
        fprintf(stream, "\ttmp[%d]           = %s\n", i, c->tmp[i]);
    }
}

void clearDefaultConfig(struct myapplicationconfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
}

void destroyDefaultConfig(struct myapplicationconfig *cfg) {
    int i;

    if assigned(cfg->bindaddress) free(cfg->bindaddress);
    cfg->bindaddress=NULL;

    if assigned(cfg->bindport) free(cfg->bindport);
    cfg->bindport=NULL;

    if assigned(cfg->wsurl) free(cfg->wsurl);
    cfg->wsurl=NULL;

    if assigned(cfg->CApath) free(cfg->CApath);
    cfg->CApath=NULL;

    if assigned(cfg->proxyurl) free(cfg->proxyurl);
    cfg->proxyurl=NULL;

    if assigned(cfg->proxyCApath) free(cfg->proxyCApath);
    cfg->proxyCApath=NULL;

    for (i=0;i<myapplicationconfig_temps;i++) {
        if assigned(cfg->tmp[i]) free(cfg->tmp[i]);
        cfg->tmp[i]=NULL;
    }
}

//////////////////////////////////////////////////////////////////////////////
typedef struct __connectionslot connectionslot_t;
typedef int myconnectionthreadfunc_t(connectionslot_t *mythread);
struct __connectionslot {
    atomic_bool                 inuse;
    struct myapplicationconfig  *appconfig;
//  pthread_mutex_t             mutex;

    SOCKET                      fd;
    struct sockaddr_storage     client;
    socklen_t                   clientlen;

    pthread_t                   thethread;
    myconnectionthreadfunc_t    *threadfunc;
    void                        *threadparameters;
    
    //websocket stuff
    CURL                        *curl;
    void                        *curlerrbuf;
};

//does not lock the internal mutex!
void clearConnection(connectionslot_t *c) {
    c->fd=INVALID_SOCKET;
    c->clientlen=0;
    memset(&c->client, 0, sizeof(c->client));

    c->curl=NULL;
    c->curlerrbuf=NULL;

    c->threadfunc=NULL;
    c->threadparameters=NULL;
    c->appconfig=NULL;
    atomic_store(&c->inuse, false);
}

//does not lock the internal mutex!
void clearConnections(connectionslot_t connections[], int connectionCount) {
    int i;
    for(i=0;i<connectionCount;i++) {
//      pthread_mutex_init(&connections[i].mutex, NULL);
        clearConnection(&connections[i]);
    }
}

//finds an empty slot
connectionslot_t *getconnectionslot(connectionslot_t connections[], int connectionCount) {
    connectionslot_t *slot, *result=NULL;
    bool _inuse;
    int i;

    //just a linear search - nothing fancy
    for(i=0;i<connectionCount;i++) {
        slot=&connections[i];
        _inuse=atomic_load(&slot->inuse);
        if (!(_inuse)) {
            result=slot;
            break;
        }
    }

    return result;
}

//////////////////////////////////////////////////////////////////////////////
void set_client_opts(SOCKET client) {
#if !defined(_WIN32)
    int yes = 1;
    struct timeval timeout;
    timeout.tv_sec = 31; timeout.tv_usec = 0;
    if (setsockopt (client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) DBGOUT(DBGWARN,"setsockopt SO_RCVTIMEO failed\n");
    yes=1;
    if (setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) < 0) DBGOUT(DBGWARN,"setsockopt SO_KEEPALIVE failed\n");
    yes=3;
    if (setsockopt(client, IPPROTO_TCP, TCP_KEEPIDLE, &yes, sizeof(int)) < 0) DBGOUT(DBGWARN,"setsockopt TCP_KEEPIDLE failed\n");
    yes=3;
    if (setsockopt(client, IPPROTO_TCP, TCP_KEEPINTVL, &yes, sizeof(int)) < 0) DBGOUT(DBGWARN,"setsockopt TCP_KEEPINTVL failed\n");
    yes=10;
    if (setsockopt(client, IPPROTO_TCP, TCP_KEEPCNT, &yes, sizeof(int)) < 0) DBGOUT(DBGWARN,"setsockopt TCP_KEEPCNT failed\n"); 
#endif
}


//thanks to Thomas Glanzmann (https://curl.se/mail/lib-2022-10/0088.html)
#ifndef BUFFER_SIZE
#   define BUFFER_SIZE 8192
#endif

#ifndef SOCKET_FLAGS
# define SOCKET_FLAGS (SO_REUSEADDR)
#endif
static CURL *wsconnect(connectionslot_t *slot) {
    CURL *curl = NULL;
    CURLcode ret;
    char *request, *errbuf;

    //request = malloc(BUFFER_SIZE);
    request=NULL;
    //if (assigned(request)) {
    if (1) {
        errbuf = malloc(CURL_ERROR_SIZE);
        if (assigned(errbuf)) {
            curl = curl_easy_init();
            if (assigned(curl)) {
                ret = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
                if (ret == CURLE_OK) {
                    if (slot->appconfig->verbose) ret = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
                    if (ret == CURLE_OK) {
                        //https://curl.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html
                        if (!(slot->appconfig->verifypeer)) ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
                        if (ret == CURLE_OK) {
                            if (!(slot->appconfig->verifypeer)) ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
                            if (ret == CURLE_OK) {
                                if (assigned(slot->appconfig->CApath)) ret = curl_easy_setopt(curl, CURLOPT_CAPATH, slot->appconfig->CApath);
                                if (ret == CURLE_OK) {
                                    if (assigned(slot->appconfig->proxyurl)) ret = curl_easy_setopt(curl, CURLOPT_PROXY, slot->appconfig->proxyurl);
                                    if (ret == CURLE_OK) {
                                        //https://curl.se/libcurl/c/CURLOPT_PROXY_SSL_VERIFYPEER.html
                                        if (assigned(slot->appconfig->proxyurl)) if (!(slot->appconfig->verifyproxy)) ret = curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 0L);
                                        if (ret == CURLE_OK) {
                                            if (assigned(slot->appconfig->proxyurl)) if (!(slot->appconfig->verifyproxy)) ret = curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 0L);
                                            if (ret == CURLE_OK) {
                                                if (assigned(slot->appconfig->proxyurl)) if (assigned(slot->appconfig->proxyCApath)) ret = curl_easy_setopt(curl, CURLOPT_PROXY_CAPATH, slot->appconfig->proxyCApath);
                                                if (ret == CURLE_OK) {

                                                    ret = curl_easy_setopt(curl, CURLOPT_URL, slot->appconfig->wsurl);
                                                    if (ret == CURLE_OK) {
                                                        ret = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
                                                        if (ret == CURLE_OK) {
                                                            ret = curl_easy_perform(curl);
                                                            if (ret == CURLE_OK) {
                                                                slot->curl=curl;
                                                                slot->curlerrbuf=errbuf;
                                                                return curl;
                                                            } else DBGOUT(DBGERROR, "curl_easy_perform(curl): %s\n", curl_easy_strerror(ret));
                                                        } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L): %s\n", curl_easy_strerror(ret));
                                                    } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_URL, \"%s\"): %s\n", slot->appconfig->wsurl, curl_easy_strerror(ret));
                                                } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_PROXY_CAPATH, %s): %s\n", curl_easy_strerror(ret), slot->appconfig->proxyCApath);
                                            } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYHOST, 0L): %s\n", curl_easy_strerror(ret)); 
                                        } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_PROXY_SSL_VERIFYPEER, 0L): %s\n", curl_easy_strerror(ret));
                                    } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_PROXY, \"%s\"): %s\n", slot->appconfig->proxyurl, curl_easy_strerror(ret));
                                } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_CAPATH, %s): %s\n", curl_easy_strerror(ret), slot->appconfig->CApath);
                            } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L): %s\n", curl_easy_strerror(ret));
                        } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L): %s\n", curl_easy_strerror(ret));
                    } else DBGOUT(DBGERROR, "curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L): %s\n", curl_easy_strerror(ret));
                } else DBGOUT(DBGERROR,"curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf): %s\n", curl_easy_strerror(ret));
                curl_easy_cleanup(curl); curl=NULL;
            } else DBGOUT(DBGERROR,"curl_easy_init failed\n");
            FREE(errbuf);
        } else DBGOUT(DBGERROR,"malloc failed\n");
        if (assigned(request)) FREE(request);
    } else DBGOUT(DBGERROR,"malloc failed\n");

    return NULL;
}

int clientConnectionThread(connectionslot_t *slot) {
    CURL *curl = NULL;
    bool _doExit=false;
    long remotefd;;
    CURLcode ret;

    DBGOUT(DBGINFO, "thread %p has started\n", slot);

    //modify local client socket
    //set_client_opts(slot->fd);

    //establish websocket connection
    curl =  wsconnect(slot);
    if (assigned(curl)) {
        ret = curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, &remotefd);
        if (ret == CURLE_OK) {
            if (ISSELECTSOCKET((SOCKET)remotefd)) {
                fd_set in, out, err;
                struct timeval timeout;
                char from[BUFFER_SIZE], to[BUFFER_SIZE];
#if HANDLE_WSPING
                char extra[BUFFER_SIZE];
                ssize_t extraidx=0;
#endif
                char *fromiptr, *fromoptr, *toiptr, *tooptr;
                unsigned int wsLastTx_msec = 0;
                int i, maxfd = -1;

                fromiptr = fromoptr = from;
                toiptr = tooptr = to;
                while (!(_doExit)) {
                    timeout.tv_sec=slot->appconfig->timout_sec; timeout.tv_usec=0;
                    FD_ZERO(&in); FD_ZERO(&out); FD_ZERO(&err);
                    
                    if (toiptr < &to[sizeof(to)]) {
                        FD_SET(slot->fd, &in);
                        if (slot->fd > maxfd) maxfd=slot->fd;
                        DBGOUT(DBGANNOUNCE, "thread %p: serversocket ready to receive (buffer %d bytes)\n", (void*)slot, (int)(toiptr-tooptr));
                    }

                    if (fromiptr < &from[sizeof(from)]) {
                         FD_SET(remotefd, &in);
                         if (remotefd > maxfd) maxfd=remotefd;
                         DBGOUT(DBGANNOUNCE, "thread %p: websocket ready to receive (buffer %d bytes)\n", (void*)slot, (int)(fromiptr-fromoptr));
                    }

#if HANDLE_WSPING
                    if ((toiptr != tooptr) || (extraidx > 0)) {
#else
                    if (toiptr != tooptr) {
#endif
                        FD_SET(remotefd, &out);
                        if (remotefd > maxfd) maxfd=remotefd;
                        DBGOUT(DBGANNOUNCE, "thread %p: websocket ready to send\n", (void*)slot);
                    } else {
                        if (slot->appconfig->wsKeepAlive_msec>0)
                            if (wsLastTx_msec >= slot->appconfig->wsKeepAlive_msec) {
                                FD_SET(remotefd, &out);
                                if (remotefd > maxfd) maxfd=remotefd;
                                DBGOUT(DBGINFO, "thread %p: websocket schedules a ping (wsLastTx_msec=%d)\n", (void*)slot, wsLastTx_msec);
                            }
                    }

                    if (fromiptr != fromoptr) {
                        FD_SET(slot->fd, &out);
                        if (slot->fd > maxfd) maxfd=slot->fd;
                        DBGOUT(DBGANNOUNCE, "thread %p: serversocket ready to send\n", (void*)slot);
                    }
                    
                    i=select(maxfd+1, &in, &out, &err, &timeout);
                    wsLastTx_msec+=(((unsigned int)slot->appconfig->timout_sec)*1000) - ((1000*timeout.tv_sec)+(timeout.tv_usec/1000));
                    DBGOUT(DBGINFO, "thread %p: select returned %i\n", (void*)slot, i);
                    if (i > 0) {
                        //select ok
                         if (i>=0) if (FD_ISSET(slot->fd, &err)) i=recv(slot->fd, NULL, 0, 0);
                         if (i>=0) if (FD_ISSET(remotefd, &err)) i=recv(remotefd, NULL, 0, 0);
                         if (i>=0) {
                             ssize_t len;
                             //read from serversocket
                             if (FD_ISSET(slot->fd, &in)) {
                                 DBGOUT(DBGANNOUNCE+2, "lifesign\n");
                                 len=recv(slot->fd, toiptr, &to[sizeof(to)] - toiptr, MSG_DONTWAIT);
                                 if (len > 0) {
                                     toiptr += len;
                                     DBGOUT(DBGINFO, "thread %p: serversocket read %d bytes\n", (void*)slot, (int)len);
                                 } else {
                                     int myerrno = EXIT_FAILURE;
                                     if (len<0) {
                                         myerrno = GETSOCKETERRNO();
                                         if (myerrno != EWOULDBLOCK && errno != EAGAIN) myerrno=EXIT_FAILURE;
                                         else                                           myerrno=EXIT_SUCCESS;
                                     }
                                     if (myerrno!=EXIT_SUCCESS) {
                                         DBGOUT(DBGERROR, "thread %p: serversocket error - read %d bytes\n", (void*)slot, (int)len);
                                         break;
                                     }
                                 }
                             }

                             //read from websocket
                             if (FD_ISSET(remotefd, &in)) {
                                 struct curl_ws_frame quirky_curl_fix;
                                 const struct curl_ws_frame *meta;
                                 DBGOUT(DBGANNOUNCE+2, "lifesign\n");
                                 ret=curl_ws_recv(curl, fromiptr, &from[sizeof(from)] - fromiptr, &len, &meta);
                                 DBGOUT(DBGANNOUNCE+2, "lifesign (curl_ws_recv()=%d, meta=%p)\n", (int)ret, (void*)meta);
                                 if ((ret == CURLE_OK) || (ret == CURLE_AGAIN)) {
                                     // CURL QUIRK
                                     if (!(assigned(meta))) {
                                         DBGOUT(DBGWARN, "thread %p: CURL QUIRK OCCURED (meta=nil) - fixing...\n", (void*)slot);
                                         memset(&quirky_curl_fix, 0, sizeof(quirky_curl_fix));
                                         meta=(const struct curl_ws_frame*)&quirky_curl_fix;
                                     }
                                     // END OF CURL QUIRK
                                     //https://curl.se/libcurl/c/curl_ws_meta.html
                                     if ((meta->flags & (CURLWS_PING | CURLWS_PONG| CURLWS_TEXT | CURLWS_CLOSE )) == 0) {
                                        if (len > 0) fromiptr += len;
                                        DBGOUT(DBGINFO, "thread %p: websocket read %d bytes\n", (void*)slot, (int)len);
                                     } else {
                                         if (meta->flags & CURLWS_PONG) {
                                             DBGOUT(DBGWARN+1, "thread %p: websocket received pong (%d bytes)\n", (void*)slot, (int)len);
#if HANDLE_WSPING
                                         } else if (meta->flags & CURLWS_PING) {
                                             ssize_t extralen=len+sizeof(len);
                                             DBGOUT(DBGWARN+1, "thread %p: websocket received ping (%d bytes)\n", (void*)slot, (int)len);
                                             if (extraidx+extralen <= sizeof(extra)) {
                                                 ssize_t *header=(void*)(&extra[extraidx]);
                                                 (*header)=len;
                                                 extraidx+=sizeof(len);
                                                 memcpy(&extra[extraidx], fromiptr, len);
                                                 extraidx+=len;
                                             } else DBGOUT(DBGWARN, "thread %p: not enough bufferspace for ping\n", (void*)slot);
#endif
                                         } else DBGOUT(DBGWARN, "thread %p: websocket received %d byte of unknown metapacket (0x%08x) - HANDLING NOT IMPLEMENTED YET\n", (void*)slot, (int)len, (int)meta->flags);
                                     }
                                 } else {
                                     DBGOUT(DBGERROR, "thread %p: websocket error during recv() (errno = %d; error: %s)\n", (void*)slot, GETSOCKETERRNO(), curl_easy_strerror(ret));
                                     break;
                                 }
                             }

                             //serversocket writable
                             if (FD_ISSET(slot->fd, &out)) {
                                 DBGOUT(DBGANNOUNCE+2, "lifesign\n");
                                 len=fromiptr-fromoptr;
                                 if (len > 0) {
                                     //there is data to send
                                     len = send(slot->fd, fromoptr, len, MSG_DONTWAIT);
                                     if (len > 0) {
                                         fsync(slot->fd);
                                         fromoptr += len;
                                         DBGOUT(DBGINFO, "thread %p: serversocket %d bytes written to\n", (void*)slot, (int)len);

                                         //pointer repair
                                         if (fromiptr == fromoptr) {
                                             fromoptr = fromiptr = from;
                                         } else {
                                             len = fromiptr - fromoptr;
                                             memmove(from, fromoptr, len);
                                             fromoptr = from;
                                             fromiptr = from + len;
                                         }
                                     } else {
                                         //error on sending via slot->fd?
                                         int myerrno = GETSOCKETERRNO();
                                         if ((myerrno != EWOULDBLOCK) && (myerrno != EAGAIN)) {
                                             DBGOUT(DBGERROR, "thread %p: serversocket error - send %d bytes\n", (void*)slot, (int)len);
                                             break;
                                         }
                                     }
                                 }
                            }

                            //websocket writable
                            if (FD_ISSET(remotefd, &out)) {
                                DBGOUT(DBGANNOUNCE+2, "lifesign\n");
                                len = toiptr - tooptr;
                                if (len > 0) {
                                    size_t sent;
                                    //there is data to send
                                    ret = curl_ws_send(curl, tooptr, len, &sent, 0, CURLWS_BINARY);
                                    if ((ret == CURLE_OK) || (ret == CURLE_AGAIN)) {
//                                      if (ret == CURLE_OK) {
                                            /* 
                                            * https://curl.se/libcurl/c/curl_ws_send.html states:
                                            * [...] sent is returned as the number of payload bytes actually sent. 
                                            */
                                            len=sent;
                                            fsync(remotefd);
                                            wsLastTx_msec=0;
                                            if (len > 0) {
                                                tooptr += len;
                                                DBGOUT(DBGINFO, "thread %p: websocket %d bytes written to\n", (void*)slot, (int)len);
                                                if (toiptr == tooptr) {
                                                    tooptr = toiptr = to;
                                                } else {
                                                    len = toiptr - tooptr;
                                                    memmove(to, tooptr, len);
                                                    tooptr = to;
                                                    toiptr = to + len;
                                                }
                                            }
//                                      } else DBGOUT(DBGWARN+1, "thread %p: websocket write needs retry\n", (void*)slot);
                                    } else {
                                        DBGOUT(DBGERROR, "thread %p: websocket error during send() (errno = %d; error: %s)\n", (void*)slot, GETSOCKETERRNO(), curl_easy_strerror(ret));
                                        break;
                                    }
                                } else {
#if HANDLE_WSPING
                                    if (extraidx >= sizeof(len)) {
                                        //send some pongs
                                        ssize_t *header=(void*)extra;
                                        ssize_t fulllen = (*header)+sizeof(len);
                                        if (extraidx < fulllen) fulllen=extraidx;
                                        ret = curl_ws_send(curl, &extra[sizeof(len)], fulllen-sizeof(len), &len, 0, CURLWS_PONG);
                                        if ((ret == CURLE_OK) || (ret == CURLE_AGAIN)) {
                                            if (ret == CURLE_OK) {
                                                if (len == (fulllen-sizeof(len))) {
                                                    DBGOUT(DBGINFO, "thread %p: websocket pong with %d bytes\n", (void*)slot, (int)len);
                                                } else {
                                                    DBGOUT(DBGWARN, "thread %p: websocket pong %d bytes but %d bytes sent\n", (void*)slot, (int)(fulllen-sizeof(len)), (int)len);
                                                }
                                                extraidx-=fulllen;
                                                if (extraidx>0) memmove(extra, &extra[fulllen], extraidx);
                                            } else DBGOUT(DBGWARN+1, "thread %p: websocket pong needs retry\n", (void*)slot);
                                        } else {
                                            DBGOUT(DBGERROR, "thread %p: websocket error during pong() (errno = %d; error: %s)\n", (void*)slot, GETSOCKETERRNO(), curl_easy_strerror(ret));
                                            break;
                                        }
                                    } else 
#endif
                                    if (slot->appconfig->wsKeepAlive_msec>0) {
                                        if (wsLastTx_msec >= slot->appconfig->wsKeepAlive_msec) {
                                            char *magic = slot->appconfig->tmp[0];
                                            if (!(assigned(magic))) magic="still alive";
                                            if (strlen(magic)<=0)   magic="still alive";

                                            ret = curl_ws_send(curl, magic, strlen(magic), &len, 0, CURLWS_PING);
                                            if ((ret == CURLE_OK) || (ret == CURLE_AGAIN)) {
                                                if (ret == CURLE_OK) {
                                                    wsLastTx_msec=0;
                                                    if (len==strlen(magic)) {
                                                        DBGOUT(DBGINFO, "thread %p: websocket ping with %d bytes\n", (void*)slot, (int)len);
                                                    } else {
                                                        DBGOUT(DBGWARN, "thread %p: websocket ping %d bytes but %d bytes sent\n", (void*)slot, (int)strlen(magic), (int)len);
                                                    }
                                                } else DBGOUT(DBGWARN+1, "thread %p: websocket ping needs retry\n", (void*)slot);
                                            } else {
                                                DBGOUT(DBGERROR, "thread %p: websocket error during ping() (errno = %d; error: %s)\n", (void*)slot, GETSOCKETERRNO(), curl_easy_strerror(ret));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                         } else {
                             DBGOUT(DBGERROR, "thread %p: socket error occured\n", (void*)slot);
                             break;
                         }
                    } else if (i < 0) {
                        //error on select
                        DBGOUT(DBGERROR, "thread %p: select returned negative\n", (void*)slot);
                        break;
                    }

                    if (!_doExit) _doExit=atomic_load(&doExit);
                }
            } else DBGOUT(DBGERROR, "remote socket not slectable\n");
        } else DBGOUT(DBGERROR, "error: %s\n", curl_easy_strerror(ret));

        DBGOUT(DBGINFO, "thread %p stopping...\n", slot);
        curl_easy_cleanup(curl); curl=NULL;
        slot->curl=NULL; FREE(slot->curlerrbuf);
    } else DBGOUT(DBGERROR, "error connecting websocket\n");

    if (ISVALIDSOCKET(slot->fd)) CLOSESOCKET(slot->fd);
    clearConnection(slot);
//  pthread_mutex_unlock(&slot->mutex);
    return EXIT_SUCCESS;
}

void *slot_threadFunc (void *args) {
    connectionslot_t *slot = args;
    slot->threadfunc(slot);
    return NULL;
}

int slot_startThread(connectionslot_t *slot) {
    int result = EXIT_SUCCESS;
    if (pthread_create(&slot->thethread, NULL, slot_threadFunc, (void*)slot) != 0) result=EXIT_FAILURE;
    return result;
}

//////////////////////////////////////////////////////////////////////////////
SOCKET startlisten(char *ip, char *port) {
    struct addrinfo hints;
    struct addrinfo *bind_address=NULL, *rp;
    SOCKET socket_listen, result=INVALID_SOCKET;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    DBGOUT(DBGINFO, "Configuring local address...\n");
    getaddrinfo(ip, port, &hints, &bind_address);

    if (assigned(bind_address)) {
        rp=bind_address;
        while (assigned(rp)) {
            if (rp!=bind_address) DBGOUT(DBGINFO, "Retrying different address...\n");
            DBGOUT(DBGINFO, "Creating socket...\n");
            socket_listen = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (ISVALIDSOCKET(socket_listen)) {
                DBGOUT(DBGINFO, "Binding socket to local address...\n");
                if (myOK(bind(socket_listen, rp->ai_addr, rp->ai_addrlen))) {
                    DBGOUT(DBGINFO, "Listening...\n");
                    if (listen(socket_listen, 3) >= 0) {
                        result=socket_listen;
                        break;
                    } else DBGOUT(DBGERROR, "listen() failed. (%d)\n", GETSOCKETERRNO());
                } else DBGOUT(DBGERROR, "bind() failed. (%d)\n", GETSOCKETERRNO());
            } else DBGOUT(DBGERROR, "socket() failed. (%d)\n", GETSOCKETERRNO());
            rp=rp->ai_next;
        }
        freeaddrinfo(bind_address);
    } else  DBGOUT(DBGERROR, "bind_addressis NULL\n");

    return result;
}

#include <getopt.h>
#include <libgen.h>


int strdup_replace(char **tobereplaced, const char *s) {
    char *tmp=strdup(s);
    if (assigned(tmp)) {
        if (assigned(*tobereplaced)) FREE(*tobereplaced);
        (*tobereplaced)=tmp;
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

static struct option long_options[] = {
    {"help"       , no_argument      , 0,  'h' },
    {"url"        , required_argument, 0,  'u' },
    {"dumpconfig" , no_argument      , 0,  'd' },
    {"verbose"    , no_argument      , 0,  'v' },
    {"bindaddress", required_argument, 0,  'a' },
    {"bindport"   , required_argument, 0,  'p' },
    {"keepalive"  , required_argument, 0,  'k' },
    {"timeout"    , required_argument, 0,  't' },
    {"proxy"      , required_argument, 0,  321 },
    {"unsecure"   , no_argument      , 0,  320 },
    {"tmp0"       , required_argument, 0,  319 },
    {"capath"     , required_argument, 0,  318 },
    {0            , 0                , 0,   0  }
};

void usage(FILE *stream, int argc, char **argv) {
    fprintf(stream, "%s VERSION %s by S. Bärwolf (tinyusbboard@matrixstorm.com) usage:\n", basename(argv[0]),MYVERSION);
    fprintf(stream, "\n");
    fprintf(stream, "\t -h/--help \t\t\t\t\t\t this help\n");
    fprintf(stream, "\n");
    fprintf(stream, "\t -u/--url <wss://user:password@domain:port/websocket>  \t the websocket-url to relay to\n");
    fprintf(stream, "\t --proxy <http://user:password@domain:port/>  \t\t the address for an proxy server to establish connections to websocket, not using \"--proxy\" means direct connection\n");
    fprintf(stream, "\t --capath </etc/ssl/certs/> \t\t\t\t path to directory filled with files of trusted certificate authorities\n");
    fprintf(stream, "\t --unsecure \t\t\t\t\t\t do not check security/certificates - force connection\n");
    fprintf(stream, "\n");
    fprintf(stream, "\t -a/--bindaddress <localhost|127.0.0.1|0.0.0.0>  \t the IP address the service listens to for incoming connections\n");
    fprintf(stream, "\t -p/--bindport <41024>  \t\t\t\t the TCP portnumber the service listens to for incoming connections\n");
    fprintf(stream, "\n");
    fprintf(stream, "\t -k/--keepalive <45>  \t\t\t\t\t the number of seconds of tolerated inactivity before sending ping (0 means deactivate)\n");
    fprintf(stream, "\t -t/--timeout   <15>  \t\t\t\t\t the maximum number of seconds waiting before polling the connectionstate (should be smaller then keepalive)\n");
    fprintf(stream, "\t -v/--verbose \t\t\t\t\t\t put libcurl in verbose mode an output more debug information\n");
    fprintf(stream, "\t -d/--dumpconfig \t\t\t\t\t after start print current settings to stderr\n");
    fprintf(stream, "\n\n");

    fprintf(stream, "%s is a very simplistic tool to make websocketes accessable via normal sockets. Usually this enables traditional tools connecting services hidden behind websockets.\n", basename(argv[0]));
    fprintf(stream, "%s therefore creates a new listening socket on the local machine and bit-bangs data from incoming connections to the websocket. This version can handle %i concurrent connections.\n", basename(argv[0]), (int)(MYMAXCONNECTIONS));
    {
        //https://curl.se/libcurl/c/curl_version_info.html
        curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
        if assigned(ver) {
            size_t i=0;
            char *wsssupport="\033[31;1mNO WEBSOCKET SUPPORT\033[0m";
            if assigned(ver->protocols) {
                while (1) {
                    if (!assigned(ver->protocols[i])) break; 
                    DBGOUT(25, "%s\n", ver->protocols[i]);
                    if (strcmp(ver->protocols[i], "wss")==0) {
                        wsssupport="secure websockets supported";
                        break;
                    } else if (strcmp(ver->protocols[i], "ws")==0) {
                        wsssupport="websockets supported";
                    }
                    i++;
                }
            }
            fprintf(stream, "%s is based on libcurl and needs quite a recent one (implementing websockets). Your currently used libcurl is: %s (%s)\n", basename(argv[0]), ver->version, wsssupport);
        }
    }

    fprintf(stream, "\n");
    fprintf(stream, "calling example: %s --dumpconfig --url wss://user:password@demo.matrixstorm.com/localhost:22 --timeout 17 --keepalive 30 --bindport 41022\n", basename(argv[0]));
    fprintf(stream, "CTRL+C will initiate service exit\n");
    fprintf(stream, "\n");
}

int main(int argc, char **argv) {
    struct myapplicationconfig appconfig;
    connectionslot_t connections[MYMAXCONNECTIONS];

    curl_global_init(CURL_GLOBAL_DEFAULT);
    clearDefaultConfig(&appconfig);
    clearConnections(connections, MYMAXCONNECTIONS);

    if (myOK(setDefaultConfig(&appconfig))) {
        SOCKET server=INVALID_SOCKET;
        struct timeval timeout;
        fd_set master;
        int i;

        //parse application options
        while (1) {
            int option_index = 0;
            i=getopt_long(argc, argv, "vhdu:a:p:kt:", long_options, &option_index);
            if (i<0) break;

            switch (i) {
                case 318 : { strdup_replace(&appconfig.proxyCApath, optarg); strdup_replace(&appconfig.CApath, optarg); break; }
                case 319 : { strdup_replace(&appconfig.tmp[0], optarg); break; }
                case 320 : { appconfig.verifypeer=false; appconfig.verifyproxy=false; break; }
                case 321 : { strdup_replace(&appconfig.proxyurl, optarg); break; }
                case 'a' : { strdup_replace(&appconfig.bindaddress, optarg); break; }
                case 'p' : { strdup_replace(&appconfig.bindport, optarg); break; }
                case 'u' : { strdup_replace(&appconfig.wsurl, optarg); break; }
                case 'd' : { appconfig.verbosedump=true; break; }
                case 'v' : { appconfig.verbose=true; break; }
                case 'h' : { usage(stderr, argc, argv); goto application_fin; }
                case 'k' :
                case 't' : { 
                    long l=strtol(optarg, NULL, 10);
                    if ((l>0)&&(l<(INT_MAX/1000))) {
                        switch (i) {
                            case 'k' : { appconfig.wsKeepAlive_msec=1000*l; break; }
                            case 't' : { appconfig.timout_sec=l; break; }
                        }
                    } break;
                }
                
                default:
                    DBGOUT(DBGWARN,"unknown option selected\n");
            }
        }
        
        //fix some config
        if (appconfig.wsKeepAlive_msec< 0) appconfig.wsKeepAlive_msec=0;
        if (appconfig.timout_sec      <=0) appconfig.timout_sec=1;
        
        //dump current config
        if (appconfig.verbosedump) {
            DBGOUT(DBGWARN,"current application config:\n");
            printConfig(stderr, &appconfig);
            fprintf(stderr,"\n");
        }

        //configure signal handlers
        install_handlers();

        // main part waiting for incoming connections
        server=startlisten(appconfig.bindaddress, appconfig.bindport);
        if (ISSELECTSOCKET(server)) {
            bool shallExit=false;
            while (1) {
                shallExit=atomic_load(&doExit);
                if (shallExit) break;

                //just process incoming connections
                FD_ZERO(&master);
                FD_SET(server, &master);

                //every 10sec give a lifesign...
                timeout.tv_sec=appconfig.timout_sec; timeout.tv_usec=0;
                i=select(server+1, &master, 0, 0, &timeout);
                DBGOUT(DBGANNOUNCE, "select()=%i\n", i);

                if (i > 0) {
                    if (FD_ISSET(server, &master)) {
                        connectionslot_t *slot=getconnectionslot(connections, MYMAXCONNECTIONS);
                        if (assigned(slot)) {
                            DBGOUT(DBGINFO, "connection attempt at free slot %p\n", (void*)slot);
                            atomic_store(&slot->inuse, true);
                            slot->fd=accept(server, (struct sockaddr*) &slot->client, &slot->clientlen);
                            if (ISSELECTSOCKET(slot->fd)) {
                                DBGOUT(DBGINFO, "accepting connection socket (%d) on slot %p\n", (int)slot->fd, (void*)slot);
                                //start the thread
                                slot->appconfig=&appconfig;
                                slot->threadfunc=&clientConnectionThread;
                                if (!myOK(slot_startThread(slot))) {
                                    DBGOUT(DBGERROR, "error spawning thread %p\n", (void*)slot);
                                    CLOSESOCKET(slot->fd);
                                    clearConnection(slot);
                                }
                            } else {
                                if (ISVALIDSOCKET(slot->fd)) {
                                    DBGOUT(DBGERROR, "accept returned socket too big for select() (%d)\n", (int)slot->fd);
                                    CLOSESOCKET(slot->fd);
                                    slot->fd=INVALID_SOCKET;
                                } else {
                                    DBGOUT(DBGERROR, "accept returned error (%d)\n", GETSOCKETERRNO());
                                }
                                atomic_store(&slot->inuse, false);
                            }
                        } else { // no more free slots
                            SOCKET fs;
                            DBGOUT(DBGERROR, "no free connection-slot left\n");
                            fs=accept(server, NULL, NULL);
                            if (ISVALIDSOCKET(fs)) CLOSESOCKET(fs);
                        }
                    } else {
                        //WE ONLY SELECT THE SERVER SOCKET
                        //THIS SHOULD NOT HAPPEN
                        assert(false);
                    }
                } else if (i < 0) {
                    DBGOUT(DBGERROR, "select returned error\n");
                    break;
                }
            }

            if (ISVALIDSOCKET(server)) CLOSESOCKET(server);

            //here we could atomic_set doExit to "true" in order NOT to wait indefinitivly for our threads in case we break while due to errors
            //however for now we don't and server our threads till they finish - we just won't accept further connections
            DBGOUT(DBGINFO,"waiting for unfinished threads to close...\n");
            for (i=0;i<MYMAXCONNECTIONS;i++) {
                connectionslot_t *slot=&connections[i];
                shallExit=atomic_load(&slot->inuse);
                if (shallExit) {
                    //still in use - wait for its thread
                    DBGOUT(DBGANNOUNCE,"waiting for thread %p ...\n", (void*)slot);
                    pthread_join(slot->thethread, NULL);
                }
            }

            DBGOUT(DBGINFO,"good bye...\n");

        } else DBGOUT(DBGERROR, "failed to startup server\n");
    } else DBGOUT(DBGERROR, "error initializing application configuration\n");

application_fin:
    destroyDefaultConfig(&appconfig);
    curl_global_cleanup();

    return EXIT_SUCCESS;
}
