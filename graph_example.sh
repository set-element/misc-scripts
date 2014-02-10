#!/bin/bash
#
# Output will look like:
#
#[sc@XX]$ graph_pd
#
# 104  | #  #           #        | 104
#      | #  #           #        |
#      | # ##           #        |
#      | # ## #  #   #  #        |
#  61  | #_##_#__#___#_###_#____ |  61
#      | ####### ##  # ### #     |
#      | ##########  ##### #     |
#      | ##########  #######     |
#      | ########### ########    |
#  11  | ########### ########    |  11
#
#	packet drops: 1227
#

. ~/bin/graph.fnc
LOG_BASE="/home/bro/logs/current"
HEIGHT="10"
TMPGRAPH="/tmp/.sergls24l"

echo $HEIGHT > $TMPGRAPH

grep Dropped_Packets $LOG_BASE/notice.log |awk ' { print $1 } ' | cf | awk ' { print $3 } ' | awk -F ":" ' { print $1 } ' | sort | uniq -c | while read D
do
	N=`echo $D | awk ' { print $1 } ' `
	echo -n " $N" >> $TMPGRAPH
done

DATA=`cat $TMPGRAPH`

echo
graph $DATA
echo
echo -n "packet drops: "
grep -c Dropped_Packets $LOG_BASE/notice.log
echo
