
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "bob_server.h"

void    cb_socket(int fd, short event, void *arg)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s [fd=%d]\n", __func__, fd);
    UP_SPACE_LEVEL;
#endif 
    struct sockaddr_in  remote_addr;
    socklen_t           len = sizeof(struct sockaddr_in);
    struct h_array_client   *hclient = get_hclient(NULL);
    struct s_array_client   *client = NULL;    
   
    if ( fd == get_main_fd(0) )
    {
        int                     nsock = 0;

        nsock = accept_client(fd, &remote_addr, &len);
        client = add_client(hclient, nsock);
        event_set(  &client->ev,
                    nsock,
                    EV_READ | EV_PERSIST,
                    cb_socket,
                    &client->ev);
        event_add( &client->ev, NULL);    
    }
    else
    {
        client = get_client(hclient, fd);
        
        if (get_data(fd, client) > 0)
        {
            event_del( &client->ev);
            rem_client(hclient, client);
            close(fd);
        }
    }
#ifdef DEBUG
    DOWN_SPACE_LEVEL;
#endif
}

void    cb_sigint(int nb, short event, void *arg)
{
#ifdef DEBUG
    SPACE_RESET;
    TAB_WRITE;
    printf(" %s [nb=%d]\n", __func__, nb);
#endif
    struct event    *ev_signal = arg;

    save_file();
    event_del(ev_signal);
    exit(0);
}

void	cb_sigpipe(int nb, short event, void * arg)
{
#ifdef DEBUG
    SPACE_RESET;
    TAB_WRITE;
    printf(" %s SIGPIPE [signal=%d]\n", __func__, nb);
#endif
    struct event    *ev_signal = arg;

    event_del(ev_signal);
    return;
}


void    bob_dispatch(int fd)
{
#ifdef DEBUG
    TAB_WRITE;
    printf(" %s [fd=%d]\n", __func__, fd);
    UP_SPACE_LEVEL;
#endif
    struct event    ev_socket;
    struct event    ev_sigint;
    struct event    ev_sigterm;
    struct event    ev_sigpipe;

    event_init();
    event_set(  &ev_socket,
                fd, 
                EV_READ | EV_PERSIST, 
                cb_socket, 
                &ev_socket);
    event_set(  &ev_sigint, 
                SIGINT, 
                EV_SIGNAL | EV_PERSIST, 
                cb_sigint, 
                &ev_sigint);
    event_set(  &ev_sigterm,
                SIGTERM,
                EV_SIGNAL | EV_PERSIST,
                cb_sigint,
                &ev_sigterm);
    event_set( &ev_sigpipe,
		    SIGPIPE,
		    EV_SIGNAL | EV_PERSIST,
		    cb_sigpipe,
		    &ev_sigpipe);
    event_add(&ev_socket, NULL);
    event_add(&ev_sigint, NULL);
    event_add(&ev_sigterm, NULL);
    event_add(&ev_sigpipe, NULL);
    event_dispatch();    
}

