#!/bin/bash
#
# Uses: https://github.com/rvoicilas/inotify-tools
#
FILELIST="/home/bro/bin/bro /home/bro/bin/capstats /usr/local/sbin/tcpdump"
INOTIFYWAIT="/usr/local/bin/inotifywait"

# Infinite loop la la la
while true
do
        $INOTIFYWAIT $FILELIST --quiet --event delete_self | while read EVENT
        do
                EVENT_=`echo $EVENT | awk ' { print $2 } '`
                FILE=`echo $EVENT | awk ' { print $1 } '`

                # This event is the cleanest indicator of a make .. replace
                # which is the same as what happens for a broctl install
                if [ "$EVENT_" = "DELETE_SELF" ]
                then
                        logger "BRO setcap on $FILE"
                        # need to wait till the binary is back in place
                        # this value can prob be trimmed down a bit
                        sleep 5
                        setcap cap_net_raw,cap_net_admin=eip $FILE
                fi
        done

        # In the event that one or more of the files are not there, we add this
        # delay here to prevent the script from spinning out.
        sleep 1
done
