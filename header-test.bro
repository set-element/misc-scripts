##! Test HTTP header values for the general form of CVE-2014-6271

@load base/protocols/http/main

module HTTP;

export {
	redef enum Notice::Type += {
		HTTP_Suspicous_Client_Header,
		HTTP_Suspicous_Server_Header,
		};

	## A boolean value to determine if client header names are to be tested
	const test_client_header_names = T &redef;
	
	## A boolean value to determine if server header names are to be logged.
	const test_server_header_names = F &redef;

	## Looking for the general form:
	##  http-header = Host:() { :; }; ping
	##
	const header_pattern = /.*\(.*\).*\{.*\:.*\;.*\}/ &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! is_orig || ! c?$http )
		return;
	
	if ( test_client_header_names )
		{
			if ( header_pattern in value ) {

				NOTICE([$note=HTTP_Suspicous_Client_Header,
					$conn = c,
					$msg = fmt("%s : %s", name, value)]);
				}

		}
		
	if ( test_server_header_names )
		{
			if ( header_pattern in value ) {

				NOTICE([$note=HTTP_Suspicous_Server_Header,
					$conn = c,
					$msg = fmt("%s : %s", name, value)]);
				}

		}
	}
