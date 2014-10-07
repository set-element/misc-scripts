# Scott Campbell
# test SMTP and POP headers for "shellshock" related patterns now that 
#  an exploit has been released.
#
module MIME_SHELL;

export {

	redef enum Notice::Type += {
		MIME_Header_ShellShock,
		};

	# pattern lifted from HTTP detector...
	const shell_pattern /.*(\(|%28)(\)|%29)( |%20)(\{|%7B)/ ;

}
# end export 

# Related data structs:
#
# hlist looke like: 
#  type mime_header_list: table[count] of mime_header_rec;
# 
#  type mime_header_rec: record {
#         name: string;   ##< The header name.
#         value: string;  ##< The header value.
#     	  };
#
#

event mime_all_headers(c: connection, hlist: mime_header_list )
	{
	# run through the set of provided headers and look for suspicous values
	for ( h in hlist ) {
		if ( shell_pattern in hlist[h]$value ) {

			NOTICE([$note=MIME_Header_ShellShock, $conn = c,
				$msg=fmt("MIME header: %s : %s", hlist[h]$name, hlist[h]$value)]);


			} # end pattern match
		} # end header val list

	} # end event
