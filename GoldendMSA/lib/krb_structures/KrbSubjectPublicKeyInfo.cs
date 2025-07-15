using Asn1;

namespace GoldendMSA {
    public class KrbSubjectPublicKeyInfo {

        public KrbAlgorithmIdentifier Algorithm { get; set; }
        public byte[] SubjectPublicKey { get; set; }

        public AsnElt Encode() {
            return AsnElt.Make(
                AsnElt.SEQUENCE, new AsnElt[] {
                    Algorithm.Encode(),
                    AsnElt.MakeBitString(SubjectPublicKey)
            });

        }
    }
}
