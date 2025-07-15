using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Asn1;

namespace GoldendMSA
{
	public class PA_DMSA_KEY_PACKAGE
	{
		// KERB-DMSA-KEY-PACKAGE::= SEQUENCE {
		//	current-keys[0] SEQUENCE OF EncryptionKey,
		//  previous-keys[1] SEQUENCE OF EncryptionKey OPTIONAL,
		//  expiration-interval[2] KerberosTime,
		// fetch-interval[4] KerberosTime,
		// }

		public PA_DMSA_KEY_PACKAGE(AsnElt body) 
		{
			currentKeys = new PA_KEY_LIST_REP(body.Sub[0].Sub[0]);
			previousKeys = new PA_KEY_LIST_REP(body.Sub[1].Sub[0]);
			expirationInterval = body.Sub[2].Sub[0].GetTime();
			fetchInterval = body.Sub[3].Sub[0].GetTime();
		}
		public PA_KEY_LIST_REP currentKeys { get; set; }
		public PA_KEY_LIST_REP previousKeys { get; set; }
		public DateTime expirationInterval { get; set; }
		public DateTime fetchInterval { get; set; }
	}
}

