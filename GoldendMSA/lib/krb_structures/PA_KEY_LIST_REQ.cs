using Asn1;
using System;
using System.Text;

namespace GoldendMSA
{
    class PA_KEY_LIST_REQ
    {
        // KERB-KEY-LIST-REQ::= SEQUENCE OF Int32 -- encryption type -- 

        public AsnElt Encode()
        {
            AsnElt enctypeAsn = AsnElt.MakeInteger(Enctype);
            AsnElt enctypeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { enctypeAsn });
            return enctypeSeq;
        }

        public Int32 Enctype { get; set; }

    }
}