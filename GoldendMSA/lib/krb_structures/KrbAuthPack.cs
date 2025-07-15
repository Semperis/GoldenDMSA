using Asn1;
using System.Security.Cryptography.X509Certificates;

namespace GoldendMSA {
    public class KrbAuthPack {

        public KrbPkAuthenticator Authenticator { get; private set; }
        public KrbSubjectPublicKeyInfo ClientPublicValue { get; set; }
        public byte[] ClientDHNonce { get; set; }

        public AsnElt Encode() {
          
            return AsnElt.Make(AsnElt.SEQUENCE, 
                new AsnElt[] {
                    AsnElt.Make(AsnElt.CONTEXT,0, Authenticator.Encode()),
                    AsnElt.Make(AsnElt.CONTEXT,1, ClientPublicValue.Encode() ),
                    //AsnElt.Make(AsnElt.CONTEXT,2, new AsnElt[]{ CMSTypes } ),
                    AsnElt.Make(AsnElt.CONTEXT,3, AsnElt.MakeBlob(ClientDHNonce)) 
                });
        }
    }
}
