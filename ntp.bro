module NTP;

export {
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		NTP_Alarm,
		};

	type ntp_record: record {
		ts: time &log;
		uid: string &log;
		orig: addr &log;
		resp: addr &log;
		refid: count &default=0 &log;
		code: count &default=0 &log;
		stratum: count &default=0 &log;
		poll: count &default=0 &log;
		precision: int &default=to_int("0") &log;
		#distance: interval;
		#dispersion: interval;
		reftime: time &log;
		#orig: time;
		#rec: time;
		#xmt: time;
		excess: string &default="NULL" &log;
		};

	# The code value maps to the NTP mode type - for now I am mostly
	#  interested in control messages.
	#
	# Mode	Description
	# 0	reserved.
	# 1	Symmetric active.
	# 2	Symmetric passive.
	# 3	Client.
	# 4	Server.
	# 5	Broadcast.
	# 6	NTP control message.
	# 7	private use.
	const NTP_RESERVED = 0;
	const NTP_SYM_ACTIVE = 1;
	const NTP_SYM_PASSIVE = 2;
	const NTP_CLIENT = 3;
	const NTP_SERVER = 4;
	const NTP_BROADCAST = 5;
	const NTP_CONTROL = 6;
	const NTP_PRIVATE = 7;

	const ports = { 123/udp,};
	redef likely_server_ports += { ports };

	const log_only_control: bool = F &redef;

	} # end export


event ntp_message(c: connection, msg: ntp_msg, excess: string)
	{
	# we are handed a ntp_msg type which is slightly different than the
	#  ntp_record used for dealing with the policy side of things.

	if ( log_only_control && ( msg$code != NTP_CONTROL ) )
		return;

	local t_rec: ntp_record;

	t_rec$orig = c$id$orig_h;
	t_rec$resp = c$id$resp_h;
	t_rec$uid = c$uid;
	t_rec$ts = c$start_time;

	if ( msg?$id )
		t_rec$refid = msg$id;

	if ( msg?$code )
		t_rec$code = msg$code;

	if ( msg?$stratum )
		t_rec$stratum = msg$stratum;

	if ( msg?$poll )
		t_rec$poll = msg$poll;

	if ( msg?$precision )
		t_rec$precision = msg$precision;

	if ( msg?$ref_t )
		t_rec$reftime = msg$ref_t;

	t_rec$excess = excess;

	Log::write(LOG, t_rec);
	}

event bro_init() &priority=5
        {
        Log::create_stream(NTP::LOG, [$columns=ntp_record]);
        Analyzer::register_for_ports(Analyzer::ANALYZER_NTP, ports);
        }
