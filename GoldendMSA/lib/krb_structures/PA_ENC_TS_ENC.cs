using Asn1;
using System;
using System.Text;

namespace GoldendMSA
{
    //PA-ENC-TS-ENC   ::= SEQUENCE {
    //        patimestamp[0]               KerberosTime, -- client's time
    //        pausec[1]                    INTEGER OPTIONAL
    //}

    public class PA_ENC_TS_ENC
    {
        public PA_ENC_TS_ENC()
        {
            patimestamp = DateTime.UtcNow;
        }

        public AsnElt Encode()
        {
            AsnElt patimestampAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, patimestamp.ToString("yyyyMMddHHmmssZ"));
            AsnElt patimestampSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { patimestampAsn });
            patimestampSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, patimestampSeq);

            AsnElt totalSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { patimestampSeq });

            return totalSeq;
        }

        public DateTime patimestamp { get; set; }


    }
}