#!/bin/sh
#
# Init file for Network Rerouter Daemon
#
# chkconfig: 2345 99 01
# description: Network Rerouter Daemon (nerd)
#
# processname: nerd
# config: /etc/sysconfig/nerd
# pidfile: /var/run/nerd.pid

RETVAL=0
NERD=nerd
IPTABLES=iptables
MODPROBE=modprobe
RMMOD=rmmod

# load library functions
. /etc/rc.d/init.d/functions

# load configuration
[ -f /etc/sysconfig/nerd ] && . /etc/sysconfig/nerd
PATH="$PATH:/usr/local/sbin"

load_rules()
{
    for n in $NETWORKS
    do
        $IPTABLES -t mangle -I OUTPUT -p tcp -d "$n" -j QUEUE
    done
    $IPTABLES -t mangle -I OUTPUT -p tcp -d 127.0.0.1 --dport 1 -j QUEUE
}

unload_rules()
{
    for n in $NETWORKS
    do
        $IPTABLES -t mangle -D OUTPUT -p tcp -d "$n" -j QUEUE 2>/dev/null
    done
    $IPTABLES -t mangle -D OUTPUT -p tcp -d 127.0.0.1 --dport 1 -j QUEUE 2>/dev/null
}

start()
{
    echo -n $"Starting $NERD:"
    $MODPROBE ip_queue
    load_rules
    initlog -c "$NERD -D $OPTIONS" && success || failure
    RETVAL=$?
    [ "$RETVAL" = 0 ] && touch /var/lock/subsys/nerd
    echo
}

stop()
{
    echo -n $"Stopping $NERD:"
    if [ -n "`pidfileofproc $NERD`" ]
    then
        killproc $NERD -INT
    else
        failure $"Stopping $NERD"
    fi
    RETVAL=$?
    [ "$RETVAL" = 0 ] && rm -f /var/lock/subsys/nerd
    echo
    unload_rules
    $RMMOD ip_queue 2>/dev/null
}

stat()
{
    killproc $NERD -USR1
    status $NERD
    RETVAL=$?
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status)
        stat
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|status}"
        RETVAL=1
esac
exit $RETVAL

    
