using System;
using Asn1;
using System.Text;
using System.Collections.Generic;

namespace GoldendMSA
{
    public class KrbCredInfo
    {
        //KrbCredInfo     ::= SEQUENCE {
        //        key             [0] EncryptionKey,
        //        prealm          [1] Realm OPTIONAL,
        //        pname           [2] PrincipalName OPTIONAL,
        //        flags           [3] TicketFlags OPTIONAL,
        //        authtime        [4] KerberosTime OPTIONAL,
        //        starttime       [5] KerberosTime OPTIONAL,
        //        endtime         [6] KerberosTime OPTIONAL,
        //        renew-till      [7] KerberosTime OPTIONAL,
        //        srealm          [8] Realm OPTIONAL,
        //        sname           [9] PrincipalName OPTIONAL,
        //        caddr           [10] HostAddresses OPTIONAL
        //}

        public KrbCredInfo()
        {
            key = new EncryptionKey();

            prealm = "";

            pname = new PrincipalName();

            flags = 0;

            srealm = "";

            sname = new PrincipalName();
        }

        public AsnElt Encode()
        {
            List<AsnElt> asnElements = new List<AsnElt>();

            // key             [0] EncryptionKey
            AsnElt keyAsn = key.Encode();
            keyAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, keyAsn);
            asnElements.Add(keyAsn);


            // prealm          [1] Realm OPTIONAL
            if (!String.IsNullOrEmpty(prealm))
            {
                AsnElt prealmAsn = AsnElt.MakeString(AsnElt.UTF8String, prealm);
                prealmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, prealmAsn);
                AsnElt prealmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, prealmAsn);
                prealmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, prealmAsnSeq);

                asnElements.Add(prealmAsnSeq);
            }


            // pname           [2] PrincipalName OPTIONAL
            if ((pname.name_string != null) && (pname.name_string.Count != 0) && (!String.IsNullOrEmpty(pname.name_string[0])))
            {
                AsnElt pnameAsn = pname.Encode();
                pnameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, pnameAsn);
                asnElements.Add(pnameAsn);
            }


            // pname           [2] PrincipalName OPTIONAL
            byte[] flagBytes = BitConverter.GetBytes((UInt32)flags);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(flagBytes);
            }
            AsnElt flagBytesAsn = AsnElt.MakeBitString(flagBytes);
            AsnElt flagBytesSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { flagBytesAsn });
            flagBytesSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, flagBytesSeq);
            asnElements.Add(flagBytesSeq);


            // authtime        [4] KerberosTime OPTIONAL
            if ((authtime != null) && (authtime != DateTime.MinValue))
            {
                AsnElt authtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, authtime.ToString("yyyyMMddHHmmssZ"));
                AsnElt authtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { authtimeAsn });
                authtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4, authtimeSeq);
                asnElements.Add(authtimeSeq);
            }


            // starttime       [5] KerberosTime OPTIONAL
            if ((starttime != null) && (starttime != DateTime.MinValue))
            {
                AsnElt starttimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, starttime.ToString("yyyyMMddHHmmssZ"));
                AsnElt starttimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { starttimeAsn });
                starttimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, starttimeSeq);
                asnElements.Add(starttimeSeq);
            }


            // endtime         [6] KerberosTime OPTIONAL
            if ((endtime != null) && (endtime != DateTime.MinValue))
            {
                AsnElt endtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, endtime.ToString("yyyyMMddHHmmssZ"));
                AsnElt endtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { endtimeAsn });
                endtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, endtimeSeq);
                asnElements.Add(endtimeSeq);
            }


            // renew-till      [7] KerberosTime OPTIONAL
            if ((renew_till != null) && (renew_till != DateTime.MinValue))
            {
                AsnElt renew_tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, renew_till.ToString("yyyyMMddHHmmssZ"));
                AsnElt renew_tillSeq = AsnElt.Make(AsnElt.SEQUENCE, new[] { renew_tillAsn });
                renew_tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, renew_tillSeq);
                asnElements.Add(renew_tillSeq);
            }


            // srealm          [8] Realm OPTIONAL
            if (!String.IsNullOrEmpty(srealm))
            {
                AsnElt srealmAsn = AsnElt.MakeString(AsnElt.UTF8String, srealm);
                srealmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, AsnElt.GeneralString, srealmAsn);
                AsnElt srealmAsnSeq = AsnElt.Make(AsnElt.SEQUENCE, srealmAsn);
                srealmAsnSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, srealmAsnSeq);
                asnElements.Add(srealmAsnSeq);
            }


            // sname           [9] PrincipalName OPTIONAL
            if ((sname.name_string != null) && (sname.name_string.Count != 0) && (!String.IsNullOrEmpty(sname.name_string[0])))
            {
                AsnElt pnameAsn = sname.Encode();
                pnameAsn = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, pnameAsn);
                asnElements.Add(pnameAsn);
            }


            // caddr           [10] HostAddresses OPTIONAL


            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, asnElements.ToArray());

            return seq;
        }

        public EncryptionKey key { get; set; }

        public string prealm { get; set; }

        public PrincipalName pname { get; set; }

        public Interop.TicketFlags flags { get; set; }

        public DateTime authtime { get; set; }

        public DateTime starttime { get; set; }

        public DateTime endtime { get; set; }

        public DateTime renew_till { get; set; }

        public string srealm { get; set; }

        public PrincipalName sname { get; set; }

        // caddr (optional) - skipping for now
    }
}
