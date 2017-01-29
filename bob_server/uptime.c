#include <time.h>
#include <stdio.h>

static  time_t  global_uptime = 0;

time_t  set_global_uptime(void)
{
    global_uptime = time(0);
    printf("%s\n", ctime(&global_uptime));
    return(global_uptime);
}

time_t  get_global_uptime(void)
{
    return(time(0) - global_uptime);
}
