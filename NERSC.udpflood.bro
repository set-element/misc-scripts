##! UDP Flood Detection

# ..Authors: Scott Campbell
#
# Track large volumes of UDP flows, logging at threshold    
#  conn/sec and notice at 5*threshold.
#

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/utils/time

module Flood;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		## UDP Flood
		UDP_Flood,
	};

	## UDP packets are measured over this interval
	const flood_test_interval = 1sec &redef;

	# Threshold to define what is an "interesting" number of UDP pkts/conns per sec
	# If value 5x the threshold, send a notice  otherwise just log.
	#
	const flood_threshold = 500.0 &redef;

	global Flood::data_collect: hook();

	type udp_rate: record {
		ts: time &log; 
		host: addr &log;
		rate: double &log;
		};
}

event bro_init() &priority=5
	{
	local r1 = SumStats::Reducer($stream="udp-conn", 
				    $apply=set(SumStats::SUM));

	SumStats::create([$name="udp-flood",
	                  $epoch=1sec,
	                  $reducers=set(r1),
			  $threshold = flood_threshold,
			  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
				{
				return result["udp-conn"]$sum;
				},
			  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
				{
				local ur: udp_rate;

				ur$ts = network_time();
				ur$rate = result["udp-conn"]$sum; 	
				ur$host = key$host;

				Log::write(LOG, ur);

				if ( result["udp-conn"]$sum > 5 * flood_threshold )
					{
					NOTICE( [$note=UDP_Flood, 
						 $msg=fmt("UDP stream exceeds %s/sec. COUNT @ SIP: %s @ %s", 
							5 * flood_threshold, result["udp-conn"]$sum, key$host ) ]);			
					}
	                  	} # end threshold_crossed
		]);

	Log::create_stream(Flood::LOG, [$columns=udp_rate]);
	}

function add_sumstats(id: conn_id)
	{

	if ( hook Flood::data_collect() ) {

		SumStats::observe("udp-conn",
			SumStats::Key($host=id$orig_h), 
			SumStats::Observation($num=1) );

		}
	}


event udp_request(c: connection)
	{
	add_sumstats(c$id);
	}

event udp_reply(c: connection)
	{
	add_sumstats(c$id);
	}
