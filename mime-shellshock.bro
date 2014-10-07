

export {

	redef enum Notice::Type += {
		MIME_Header_ShellShock,
		};

	const shell_pattern /.*(\(|%28)(\)|%29)( |%20)(\{|%7B)/ ;

}
# end export 

# global mime_all_headers: event(c: connection , hlist: mime_header_list );
#
# note that hlist looke like: 
#  type mime_header_list: table[count] of mime_header_rec;
# 
# type mime_header_rec: record {
#        name: string;   ##< The header name.
#        value: string;  ##< The header value.
# 	};
#
#

event mime_all_headers(c: connection, hlist: mime_header_list )
	{
	# run through the set of provided headers and look for suspicous values
	for ( h in hlist ) {
		if ( shell_pattern in h$value ) {

			NOTICE([$note=MIME_Header_ShellShock, $conn = c,
				$msg=fmt("MIME header: %s : %s", h$name, h$value)]);


			} # end pattern match
		} # end header val list

	} # end event
