#!/usr/bin/python
#
# green
#       <low threshold>
# yellow
#       <med threshold>
# purple
#       <high threshold>
# red
#
import datetime

### ---------------------
data_file = '/home/bro/logs/current/capture_loss.log'
lowThresh  = 0.2
medThresh = 1.0
highThresh = 3.0
### ---------------------

os = open(data_file)
avgStore = {}
runAvg = 0
hour_set = []
host_set = []

CSI="\x1B["
reset=CSI+"m"

for l in os.readlines():
    if ( not l.startswith("#") ):
        ll = l.split('\t')

        hour = datetime.datetime.fromtimestamp( float(ll[0]) ).hour
        host = ll[2]
        value = float(ll[5])

        if ( host not in host_set ):
            host_set.append(host)

        if ( hour not in hour_set ):
            hour_set.append(hour)

        try:
            runAvg = avgStore[host, hour]

        except KeyError:
            runAvg = value

        avgStore[host, hour] = (runAvg + value) / 2

# now loop through the data matrix and
#  print out the results
#
x_host = ""
y_hour = ""
test_val = 0.00
retValue = ""

host_set.sort()
hour_set.sort()

print
for x_host in host_set:
    print x_host, "x_host",
    for y_hour in hour_set:

        try:
            test_val = avgStore[x_host,y_hour]
        except:
            retVal = CSI+"30;40m" + u"\u2588" + CSI + "0m"

        if test_val < highThresh:
            retVal = CSI+"35;40m" + u"\u2588" + CSI + "0m"

        if test_val < medThresh:
            retVal = CSI+"33;40m" + u"\u2588" + CSI + "0m"

        if test_val < lowThresh:
            retVal = CSI+"32;40m" + u"\u2588" + CSI + "0m"

        if test_val >= highThresh:
            retVal = CSI+"31;40m" + u"\u2588" + CSI + "0m"

        print retVal,

    print

print " Hour:                 ",

for y_hour in hour_set:
    print y_hour,
