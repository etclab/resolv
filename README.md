Go package that implements a variety of DNS clients, including DNS-over-TLS and
DNS-over-HTTPS.
# resolv


# sdscan

## Output Schema

```
{   
	Rank: <int>
    QName: <string>

   	DNSSDProbe: <null> | { 
    	ServiceBrowsers: [
        	<str>,
            ... 
      	]   
        DefaultServiceBrowser: <str>
        LegacyServiceBrowsers: [
        	<str>,
           	... 
       	],  
    	Services: {
        	<str>: [
            	{   
                	Name: <str>,
                    Priority: <int>,
                    Weight: <int>,
                    Port: <int>,
                    Target: <str>,
                    Txt: <null> | [ 
                    	<str>,
                        ... 
                   	],
                   	SRVValidated: {
                    	Validated: <bool>,
                        Rcode: <int>,
                        ExtendedErrorCode: <int>
                  	},  
                    AValidated: {
                    	Validated: <bool>,
                        Rcode: <int>,
                        ExtendedErrorCode: <int>
                  	},  
                   	AAAAValidated: {
                    	Validated: <bool>,
                     	Rcode: <int>,
                        ExtendedErrorCode: <int>
                   	}   
             	},  
              	... 
          	],  
            ... 
      	}   
  	},  
        
	PTRProbe: <null> | { 
    	Services: {
        	<str>: [
            	{   
                	Name: <str>,
                    Priority: <int>,
                    Weight: <int>,
                    Port: <int>,
                    Target: <str>,
                    Txt: <null> | [ 
                    	<str>,
                      	... 
                   	],
                 	SRVValidated: {
                    	Validated: <bool>,
                        Rcode: <int>,
                        ExtendedErrorCode: <int>
                 	},  
                    AValidated: {
                    	Validated: <bool>,
                        Rcode: <int>,
                        ExtendedErrorCode: <int>
                  	},
                  	AAAAValidated: {
                    	Validated: <bool>,
                        Rcode: <int>,
                        ExtendedErrorCode: <int>
                 	}
               	},
               	...
         	],
            ...
     	}
   	},

   	NAPTRProbe: {
    	NAPTRs: [
        	{
            	Order: <int>,
                Preference: <int>,
                Flags: <str>,
                Service: <str>,
                Regexp: <str>,
                Replacement: <str>,
                NAPTRValidated: {
                	Validated: <bool>
                    Rcode: <int>,
                    ExtendedErrorCode: <int>
               	}
            	Services: nil | [
                    {
                        Name: <str>,
                        Priority: <int>,
                        Weight: <int>,
                        Port: <int>,
                        Target: <str>,
                        Txt: <null> | [
                        <str>,
                            ...
                        ],
                        SRVValidated: {
                            Validated: <bool>,
                            Rcode: <int>,
                            ExtendedErrorCode: <int>
                        },
                        AValidated: {
                            Validated: <bool>,
                            Rcode: <int>,
                            ExtendedErrorCode: <int>
                        },
                        AAAAValidated: {
                            Validated: <bool>,
                            Rcode: <int>,
                            ExtendedErrorCode: <int>
                        },
                    },
                    ...
                ]
            },
           	...
        ]
  	}
}
                                                                                                         166,0-1       Bot


