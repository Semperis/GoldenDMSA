using System;
using System.Runtime.InteropServices;


namespace GoldendMSA {
    public class Interop
    {

        public const int KRB_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP = 1;
        public const int KRB_KEY_USAGE_AS_REP_TGS_REP = 2;
        public const int KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3;
        public const int KRB_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA = 4;
        public const int KRB_KEY_USAGE_TGS_REQ_CHECKSUM = 6;
        public const int KRB_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR = 7;
        public const int KRB_KEY_USAGE_TGS_REP_EP_SESSION_KEY = 8;
        public const int KRB_KEY_USAGE_TGS_REQ_AUTHENTICATOR_CHECKSUM = 10;
        public const int KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR = 11;
        public const int KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART = 13;
        public const int KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART = 14;
        public const int KRB_KEY_USAGE_KRB_NON_KERB_SALT = 16;
        public const int KRB_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT = 17;
        public const int KRB_KEY_USAGE_PA_S4U_X509_USER = 26;


        public const int GROUP_ATTRIBUTES_DEFAULT = (int)(
            KERB_SID_AND_ATTRIBUTES_Attributes.SE_GROUP_ENABLED |
            KERB_SID_AND_ATTRIBUTES_Attributes.SE_GROUP_ENABLED_BY_DEFAULT |
            KERB_SID_AND_ATTRIBUTES_Attributes.SE_GROUP_MANDATORY
        );

        // 536870919 - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/311aab27-ebdf-47f7-b939-13dc99b15341
        public const int R_GROUP_ATTRIBUTES_DEFAULT = (int)(
            KERB_SID_AND_ATTRIBUTES_Attributes.SE_GROUP_ENABLED |
            KERB_SID_AND_ATTRIBUTES_Attributes.SE_GROUP_ENABLED_BY_DEFAULT |
            KERB_SID_AND_ATTRIBUTES_Attributes.SE_GROUP_MANDATORY |
            KERB_SID_AND_ATTRIBUTES_Attributes.SE_GROUP_RESOURCE
        );

        // Enums

        [Flags]
        public enum TicketFlags : UInt32
        {
            reserved = 2147483648,
            forwardable = 0x40000000,
            forwarded = 0x20000000,
            proxiable = 0x10000000,
            proxy = 0x08000000,
            may_postdate = 0x04000000,
            postdated = 0x02000000,
            invalid = 0x01000000,
            renewable = 0x00800000,
            initial = 0x00400000,
            pre_authent = 0x00200000,
            hw_authent = 0x00100000,
            ok_as_delegate = 0x00040000,
            anonymous = 0x00020000,
            name_canonicalize = 0x00010000,
            //cname_in_pa_data = 0x00040000,
            enc_pa_rep = 0x00010000,
            reserved1 = 0x00000001,
            empty = 0x00000000
            // TODO: constrained delegation?
        }

        
        [Flags]
        public enum KdcOptions : uint
        {
            VALIDATE = 0x00000001,
            RENEW = 0x00000002,
            UNUSED29 = 0x00000004,
            ENCTKTINSKEY = 0x00000008,
            RENEWABLEOK = 0x00000010,
            DISABLETRANSITEDCHECK = 0x00000020,
            UNUSED16 = 0x0000FFC0,
            CONSTRAINED_DELEGATION = 0x00020000,
            CANONICALIZE = 0x00010000,
            CNAMEINADDLTKT = 0x00004000,
            OK_AS_DELEGATE = 0x00040000,
            REQUEST_ANONYMOUS = 0x00008000,
            UNUSED12 = 0x00080000,
            OPTHARDWAREAUTH = 0x00100000,
            PREAUTHENT = 0x00200000,
            INITIAL = 0x00400000,
            RENEWABLE = 0x00800000,
            UNUSED7 = 0x01000000,
            POSTDATED = 0x02000000,
            ALLOWPOSTDATE = 0x04000000,
            PROXY = 0x08000000,
            PROXIABLE = 0x10000000,
            FORWARDED = 0x20000000,
            FORWARDABLE = 0x40000000,
            RESERVED = 0x80000000
        }

        // from https://tools.ietf.org/html/rfc4120#section-7.5.7
        public enum KERB_MESSAGE_TYPE : long
        {
            AS_REQ = 10,
            AS_REP = 11,
            TGS_REQ = 12,
            TGS_REP = 13,
            AP_REQ = 14,
            AP_REP = 15,
            TGT_REQ = 16, // KRB-TGT-REQUEST for U2U
            TGT_REP = 17, // KRB-TGT-REPLY for U2U
            SAFE = 20,
            PRIV = 21,
            CRED = 22,
            ERROR = 30
        }

        // from https://tools.ietf.org/html/rfc3961
        public enum KERB_ETYPE : Int32
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65,
            old_exp = -135,
            aes256_gcm_ghash_credguard = -180
        }

        
        // from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/311aab27-ebdf-47f7-b939-13dc99b15341
        [Flags]
        public enum KERB_SID_AND_ATTRIBUTES_Attributes
        {
            SE_GROUP_MANDATORY = 1,          // Group is mandatory for the user and cannot be disabled.
            SE_GROUP_ENABLED_BY_DEFAULT = 2, // Group is marked as enabled by default.
            SE_GROUP_ENABLED = 4,            // Group is enabled for use.
            SE_GROUP_OWNER = 8,              // Group can be assigned as an owner of a resource.
            SE_GROUP_RESOURCE = 536870912,   // Group is a domain-local or resource group.
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CHECKSUM
        {
            public int Type;
            public int Size;
            public int Flag;
            public IntPtr Initialize;
            public IntPtr Sum;
            public IntPtr Finalize;
            public IntPtr Finish;
            public IntPtr InitializeEx;
            public IntPtr unk0_null;
        }

        // from https://tools.ietf.org/html/rfc4120#section-6.2
        public enum PRINCIPAL_TYPE : long
        {
            NT_UNKNOWN = 0,
            NT_PRINCIPAL = 1,
            NT_SRV_INST = 2,
            NT_SRV_HST = 3,
            NT_SRV_XHST = 4,
            NT_UID = 5,
            NT_X500_PRINCIPAL = 6,
            NT_SMTP_NAME = 7,
            NT_ENTERPRISE = 10
        }

        // from https://github.com/ps4dev/freebsd-include-mirror/blob/master/krb5_asn1.h
        public enum PADATA_TYPE : UInt32
        {
            NONE = 0,
            TGS_REQ = 1,
            AP_REQ = 1,
            ENC_TIMESTAMP = 2,
            PW_SALT = 3,
            ENC_UNIX_TIME = 5,
            SANDIA_SECUREID = 6,
            SESAME = 7,
            OSF_DCE = 8,
            CYBERSAFE_SECUREID = 9,
            AFS3_SALT = 10,
            ETYPE_INFO = 11,
            SAM_CHALLENGE = 12,
            SAM_RESPONSE = 13,
            PK_AS_REQ_19 = 14,
            PK_AS_REP_19 = 15,
            PK_AS_REQ_WIN = 15,
            PK_AS_REQ = 16,
            PK_AS_REP = 17,
            PA_PK_OCSP_RESPONSE = 18,
            ETYPE_INFO2 = 19,
            USE_SPECIFIED_KVNO = 20,
            SVR_REFERRAL_INFO = 20,
            SAM_REDIRECT = 21,
            GET_FROM_TYPED_DATA = 22,
            SAM_ETYPE_INFO = 23,
            SERVER_REFERRAL = 25,
            TD_KRB_PRINCIPAL = 102,
            PK_TD_TRUSTED_CERTIFIERS = 104,
            PK_TD_CERTIFICATE_INDEX = 105,
            TD_APP_DEFINED_ERROR = 106,
            TD_REQ_NONCE = 107,
            TD_REQ_SEQ = 108,
            PA_PAC_REQUEST = 128,
            S4U2SELF = 129,
            PA_S4U_X509_USER = 130,
            PA_PAC_OPTIONS = 167,
            PK_AS_09_BINDING = 132,
            CLIENT_CANONICALIZED = 133,
            KEY_LIST_REQ = 161,
            KEY_LIST_REP = 162,
            SUPERSEDED_BY_USER = 170,
            DMSA_KEY_PACKAGE = 171
        }

        // adapted from https://github.com/skelsec/minikerberos/blob/master/minikerberos/kerberoserror.py#L18-L76
        public enum KERBEROS_ERROR : UInt32
        {
            KDC_ERR_NONE = 0x0, // No error
            KDC_ERR_NAME_EXP = 0x1, // Client's entry in KDC database has expired
            KDC_ERR_SERVICE_EXP = 0x2, // Server's entry in KDC database has expired
            KDC_ERR_BAD_PVNO = 0x3, // Requested Kerberos version number not supported
            KDC_ERR_C_OLD_MAST_KVNO = 0x4, // Client's key encrypted in old master key
            KDC_ERR_S_OLD_MAST_KVNO = 0x5, // Server's key encrypted in old master key
            KDC_ERR_C_PRINCIPAL_UNKNOWN = 0x6, // Client not found in Kerberos database
            KDC_ERR_S_PRINCIPAL_UNKNOWN = 0x7, // Server not found in Kerberos database
            KDC_ERR_PRINCIPAL_NOT_UNIQUE = 0x8, // Multiple principal entries in KDC database
            KDC_ERR_NULL_KEY = 0x9, // The client or server has a null key (master key)
            KDC_ERR_CANNOT_POSTDATE = 0xA, // Ticket (TGT) not eligible for postdating
            KDC_ERR_NEVER_VALID = 0xB, // Requested start time is later than end time
            KDC_ERR_POLICY = 0xC, // Requested start time is later than end time
            KDC_ERR_BADOPTION = 0xD, // KDC cannot accommodate requested option
            KDC_ERR_ETYPE_NOTSUPP = 0xE, // KDC has no support for encryption type
            KDC_ERR_SUMTYPE_NOSUPP = 0xF, // KDC has no support for checksum type
            KDC_ERR_PADATA_TYPE_NOSUPP = 0x10, // KDC has no support for PADATA type (pre-authentication data)
            KDC_ERR_TRTYPE_NO_SUPP = 0x11, // KDC has no support for transited type
            KDC_ERR_CLIENT_REVOKED = 0x12, // Client’s credentials have been revoked
            KDC_ERR_SERVICE_REVOKED = 0x13, //Credentials for server have been revoked
            KDC_ERR_TGT_REVOKED = 0x14, // TGT has been revoked
            KDC_ERR_CLIENT_NOTYET = 0x15, // Client not yet valid—try again later
            KDC_ERR_SERVICE_NOTYET = 0x16, //Server not yet valid—try again later
            KDC_ERR_KEY_EXPIRED = 0x17, // Password has expired—change password to reset
            KDC_ERR_PREAUTH_FAILED = 0x18, // Pre-authentication information was invalid
            KDC_ERR_PREAUTH_REQUIRED = 0x19, // Additional preauthentication required
            KDC_ERR_SERVER_NOMATCH = 0x1A, // KDC does not know about the requested server
            KDC_ERR_MUST_USE_USER2USER = 0x1B, // Server principal valid for user2user only
            KDC_ERR_PATH_NOT_ACCEPTED = 0x1C, // KDC Policy rejects transited path
            KDC_ERR_SVC_UNAVAILABLE = 0x1D, // KDC is unavailable (modified as stated here: https://github.com/dotnet/Kerberos.NET/blob/develop/Kerberos.NET/Entities/Krb/KerberosErrorCode.cs)
            KRB_AP_ERR_BAD_INTEGRITY = 0x1F, // Integrity check on decrypted field failed
            KRB_AP_ERR_TKT_EXPIRED = 0x20, // The ticket has expired
            KRB_AP_ERR_TKT_NYV = 0x21, // The ticket is not yet valid
            KRB_AP_ERR_REPEAT = 0x22, // The request is a replay
            KRB_AP_ERR_NOT_US = 0x23, // The ticket is not for us
            KRB_AP_ERR_BADMATCH = 0x24, //The ticket and authenticator do not match
            KRB_AP_ERR_SKEW = 0x25, // The clock skew is too great
            KRB_AP_ERR_BADADDR = 0x26, // Network address in network layer header doesn't match address inside ticket
            KRB_AP_ERR_BADVERSION = 0x27, // Protocol version numbers don't match (PVNO)
            KRB_AP_ERR_MSG_TYPE = 0x28, // Message type is unsupported
            KRB_AP_ERR_MODIFIED = 0x29, // Message stream modified and checksum didn't match
            KRB_AP_ERR_BADORDER = 0x2A, // Message out of order (possible tampering)
            KRB_AP_ERR_BADKEYVER = 0x2C, // Specified version of key is not available
            KRB_AP_ERR_NOKEY = 0x2D, // Service key not available
            KRB_AP_ERR_MUT_FAIL = 0x2E, // Mutual authentication failed
            KRB_AP_ERR_BADDIRECTION = 0x2F, // Incorrect message direction
            KRB_AP_ERR_METHOD = 0x30, // Alternative authentication method required
            KRB_AP_ERR_BADSEQ = 0x31, // Incorrect sequence number in message
            KRB_AP_ERR_INAPP_CKSUM = 0x32, // Inappropriate type of checksum in message (checksum may be unsupported)
            KRB_AP_PATH_NOT_ACCEPTED = 0x33, // Desired path is unreachable
            KRB_ERR_RESPONSE_TOO_BIG = 0x34, // Too much data
            KRB_ERR_GENERIC = 0x3C, // Generic error; the description is in the e-data field
            KRB_ERR_FIELD_TOOLONG = 0x3D, // Field is too long for this implementation
            KDC_ERR_CLIENT_NOT_TRUSTED = 0x3E, // The client trust failed or is not implemented
            KDC_ERR_KDC_NOT_TRUSTED = 0x3F, // The KDC server trust failed or could not be verified
            KDC_ERR_INVALID_SIG = 0x40, // The signature is invalid
            KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED = 0x41, // KDC policy has determined the provided Diffie-Hellman key parameters are not acceptable
            KDC_ERR_CERTIFICATE_MISMATCH = 0x42, // certificate doesn't match client user
            KRB_AP_ERR_NO_TGT = 0x43, // No TGT was presented or available
            KDC_ERR_WRONG_REALM = 0x44, //Incorrect domain or principal
            KRB_AP_ERR_USER_TO_USER_REQUIRED = 0x45, // Ticket must be for USER-TO-USER
            KDC_ERR_CANT_VERIFY_CERTIFICATE = 0x46,
            KDC_ERR_INVALID_CERTIFICATE = 0x47,
            KDC_ERR_REVOKED_CERTIFICATE = 0x48,
            KDC_ERR_REVOCATION_STATUS_UNKNOWN = 0x49,
            KDC_ERR_CLIENT_NAME_MISMATCH = 0x4B,
            KDC_ERR_KDC_NAME_MISMATCH = 0x4C,
            KDC_ERR_INCONSISTENT_KEY_PURPOSE = 0x4D, // The client certificate does not contain the KeyPurposeId EKU and is required
            KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED = 0x4E, // The signature algorithm used to sign the CA certificate is not accepted
            KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED = 0x4F, // The client did not include the required paChecksum parameter
            KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED = 0x50, // The signature algorithm used to sign the request is not accepted
            KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = 0x51, // The KDC does not support public key encryption for PKINIT
            KRB_AP_ERR_PRINCIPAL_UNKNOWN = 0x52, // A well-known Kerberos principal name is used but not supported
            KRB_AP_ERR_REALM_UNKNOWN = 0x53, // A well-known Kerberos realm name is used but not supported
            KRB_AP_ERR_PRINCIPAL_RESERVED = 0x54, // A reserved Kerberos principal name is used but not supported
            KDC_ERR_PREAUTH_EXPIRED = 0x5A, // The provided pre-auth data has expired
            KDC_ERR_MORE_PREAUTH_DATA_REQUIRED = 0x5B, // The KDC found the presented pre-auth data incomplete and requires additional information
            KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET = 0x5C, // The client sent an authentication set that the KDC was not expecting
            KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS = 0x5D, // The provided FAST options that were marked as critical are unknown to the KDC and cannot be processed
        }


        public enum KERB_PROTOCOL_MESSAGE_TYPE : UInt32
        {
            KerbDebugRequestMessage = 0,
            KerbQueryTicketCacheMessage = 1,
            KerbChangeMachinePasswordMessage = 2,
            KerbVerifyPacMessage = 3,
            KerbRetrieveTicketMessage = 4,
            KerbUpdateAddressesMessage = 5,
            KerbPurgeTicketCacheMessage = 6,
            KerbChangePasswordMessage = 7,
            KerbRetrieveEncodedTicketMessage = 8,
            KerbDecryptDataMessage = 9,
            KerbAddBindingCacheEntryMessage = 10,
            KerbSetPasswordMessage = 11,
            KerbSetPasswordExMessage = 12,
            KerbVerifyCredentialsMessage = 13,
            KerbQueryTicketCacheExMessage = 14,
            KerbPurgeTicketCacheExMessage = 15,
            KerbRefreshSmartcardCredentialsMessage = 16,
            KerbAddExtraCredentialsMessage = 17,
            KerbQuerySupplementalCredentialsMessage = 18,
            KerbTransferCredentialsMessage = 19,
            KerbQueryTicketCacheEx2Message = 20,
            KerbSubmitTicketMessage = 21,
            KerbAddExtraCredentialsExMessage = 22,
            KerbQueryKdcProxyCacheMessage = 23,
            KerbPurgeKdcProxyCacheMessage = 24,
            KerbQueryTicketCacheEx3Message = 25,
            KerbCleanupMachinePkinitCredsMessage = 26,
            KerbAddBindingCacheEntryExMessage = 27,
            KerbQueryBindingCacheMessage = 28,
            KerbPurgeBindingCacheMessage = 29,
            KerbQueryDomainExtendedPoliciesMessage = 30,
            KerbQueryS4U2ProxyCacheMessage = 31
        }

        public enum SecBufferType
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_EMPTY = 0,
            SECBUFFER_DATA = 1,
            SECBUFFER_TOKEN = 2
        }

        // from https://directory.apache.org/apacheds/gen-docs/2.0.0-M15/apidocs/src-html/org/apache/directory/shared/kerberos/codec/types/HostAddrType.html
        public enum HostAddressType : long
        {
            NULL = 0,
            ADDRTYPE_UNIX = 1,
            ADDRTYPE_INET = 2,
            ADDRTYPE_IMPLINK = 3,
            ADDRTYPE_PUP = 4,
            ADDRTYPE_CHAOS = 5,
            ADDRTYPE_XNS = 6,
            ADDRTYPE_IPX = 6,
            ADDRTYPE_OSI = 7,
            ADDRTYPE_ECMA = 8,
            ADDRTYPE_DATAKIT = 9,
            ADDRTYPE_CCITT = 10,
            ADDRTYPE_SNA = 11,
            ADDRTYPE_DECNET = 12,
            ADDRTYPE_DLI = 13,
            ADDRTYPE_LAT = 14,
            ADDRTYPE_HYLINK = 15,
            ADDRTYPE_APPLETALK = 16,
            ADDRTYPE_VOICEVIEW = 18,
            ADDRTYPE_FIREFOX = 19,
            ADDRTYPE_NETBIOS = 20,
            ADDRTYPE_BAN = 21,
            ADDRTYPE_ATM = 22,
            ADDRTYPE_INET6 = 24
        }


        // From Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1773-L1794
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ECRYPT
        {
            int Type0;
            public int BlockSize;
            int Type1;
            public int KeySize;
            public int Size;
            int unk2;
            int unk3;
            public IntPtr AlgName;
            public IntPtr Initialize;
            public IntPtr Encrypt;
            public IntPtr Decrypt;
            public IntPtr Finish;
            public IntPtr HashPassword;
            IntPtr RandomKey;
            IntPtr Control;
            IntPtr unk0_null;
            IntPtr unk1_null;
            IntPtr unk2_null;
        }


        // LSA structures

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_SUBMIT_TKT_REQUEST
        {
            public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
            public LUID LogonId;
            public int Flags;
            public KERB_CRYPTO_KEY32 Key; // key to decrypt KERB_CRED
            public int KerbCredSize;
            public int KerbCredOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CRYPTO_KEY32
        {
            public int KeyType;
            public int Length;
            public int Offset;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_STRING_IN
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public string Buffer;
            public LSA_STRING_IN(string value) {
                Length = (ushort)value.Length;
                MaximumLength = (ushort)(value.Length + 1);
                Buffer = value;
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SecBuffer : IDisposable
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;


            public SecBuffer(int bufferSize)
            {
                cbBuffer = bufferSize;
                BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(bufferSize);
            }

            public SecBuffer(byte[] secBufferBytes)
            {
                cbBuffer = secBufferBytes.Length;
                BufferType = (int)SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public SecBuffer(byte[] secBufferBytes, SecBufferType bufferType)
            {
                cbBuffer = secBufferBytes.Length;
                BufferType = (int)bufferType;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }
        }

        public struct MultipleSecBufferHelper
        {
            public byte[] Buffer;
            public SecBufferType BufferType;

            public MultipleSecBufferHelper(byte[] buffer, SecBufferType bufferType)
            {
                if (buffer == null || buffer.Length == 0)
                {
                    throw new ArgumentException("buffer cannot be null or 0 length");
                }

                Buffer = buffer;
                BufferType = bufferType;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SecBufferDesc : IDisposable
        {

            public int ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; //Point to SecBuffer

            public SecBufferDesc(int bufferSize)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer ThisSecBuffer = new SecBuffer(bufferSize);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
                Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
            }

            public SecBufferDesc(byte[] secBufferBytes)
            {
                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = 1;
                SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytes);
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(ThisSecBuffer));
                Marshal.StructureToPtr(ThisSecBuffer, pBuffers, false);
            }

            public SecBufferDesc(MultipleSecBufferHelper[] secBufferBytesArray)
            {
                if (secBufferBytesArray == null || secBufferBytesArray.Length == 0)
                {
                    throw new ArgumentException("secBufferBytesArray cannot be null or 0 length");
                }

                ulVersion = (int)SecBufferType.SECBUFFER_VERSION;
                cBuffers = secBufferBytesArray.Length;

                //Allocate memory for SecBuffer Array....
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)) * cBuffers);

                for (int Index = 0; Index < secBufferBytesArray.Length; Index++)
                {
                    //Super hack: Now allocate memory for the individual SecBuffers
                    //and just copy the bit values to the SecBuffer array!!!
                    SecBuffer ThisSecBuffer = new SecBuffer(secBufferBytesArray[Index].Buffer, secBufferBytesArray[Index].BufferType);

                    //We will write out bits in the following order:
                    //int cbBuffer;
                    //int BufferType;
                    //pvBuffer;
                    //Note that we won't be releasing the memory allocated by ThisSecBuffer until we
                    //are disposed...
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                    Marshal.WriteInt32(pBuffers, CurrentOffset, ThisSecBuffer.cbBuffer);
                    Marshal.WriteInt32(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer), ThisSecBuffer.BufferType);
                    Marshal.WriteIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(ThisSecBuffer.cbBuffer) + Marshal.SizeOf(ThisSecBuffer.BufferType), ThisSecBuffer.pvBuffer);
                }
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    if (cBuffers == 1)
                    {
                        SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                        ThisSecBuffer.Dispose();
                    }
                    else
                    {
                        for (int Index = 0; Index < cBuffers; Index++)
                        {
                            //The bits were written out the following order:
                            //int cbBuffer;
                            //int BufferType;
                            //pvBuffer;
                            //What we need to do here is to grab a hold of the pvBuffer allocate by the individual
                            //SecBuffer and release it...
                            int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                            IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                            Marshal.FreeHGlobal(SecBufferpvBuffer);
                        }
                    }

                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            public byte[] GetSecBufferByteArray()
            {
                byte[] Buffer = null;

                if (pBuffers == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Object has already been disposed!!!");
                }

                if (cBuffers == 1)
                {
                    SecBuffer ThisSecBuffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));

                    if (ThisSecBuffer.cbBuffer > 0)
                    {
                        Buffer = new byte[ThisSecBuffer.cbBuffer];
                        Marshal.Copy(ThisSecBuffer.pvBuffer, Buffer, 0, ThisSecBuffer.cbBuffer);
                    }
                }
                else
                {
                    int BytesToAllocate = 0;

                    for (int Index = 0; Index < cBuffers; Index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //What we need to do here calculate the total number of bytes we need to copy...
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        BytesToAllocate += Marshal.ReadInt32(pBuffers, CurrentOffset);
                    }

                    Buffer = new byte[BytesToAllocate];

                    for (int Index = 0, BufferIndex = 0; Index < cBuffers; Index++)
                    {
                        //The bits were written out the following order:
                        //int cbBuffer;
                        //int BufferType;
                        //pvBuffer;
                        //Now iterate over the individual buffers and put them together into a
                        //byte array...
                        int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));
                        int BytesToCopy = Marshal.ReadInt32(pBuffers, CurrentOffset);
                        IntPtr SecBufferpvBuffer = Marshal.ReadIntPtr(pBuffers, CurrentOffset + Marshal.SizeOf(typeof(int)) + Marshal.SizeOf(typeof(int)));
                        Marshal.Copy(SecBufferpvBuffer, Buffer, BufferIndex, BytesToCopy);
                        BufferIndex += BytesToCopy;
                    }
                }

                return (Buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
            public SECURITY_INTEGER(int dummy)
            {
                LowPart = 0;
                HighPart = 0;
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
            public SECURITY_HANDLE(int dummy)
            {
                LowPart = HighPart = IntPtr.Zero;
            }
        };


        // functions

        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCheckSum);

        public delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
        public delegate int KERB_ECRYPT_Encrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        public delegate int KERB_ECRYPT_Decrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        public delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);

        public delegate int KERB_ECRYPT_HashPassword(UNICODE_STRING Password, UNICODE_STRING Salt, int count, byte[] output);


        public delegate int KERB_CHECKSUM_Initialize(int unk0, out IntPtr pContext);
        public delegate int KERB_CHECKSUM_Sum(IntPtr pContext, int Size, byte[] Buffer);
        public delegate int KERB_CHECKSUM_Finalize(IntPtr pContext, byte[] Buffer);
        public delegate int KERB_CHECKSUM_Finish(ref IntPtr pContext);
        public delegate int KERB_CHECKSUM_InitializeEx(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);

        // LSA functions

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaConnectUntrusted(
            [Out] out IntPtr LsaHandle
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaLookupAuthenticationPackage(
            [In] IntPtr LsaHandle,
            [In] ref LSA_STRING_IN PackageName,
            [Out] out int AuthenticationPackage
        );


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaNtStatusToWinError(
            uint status
        );


        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaCallAuthenticationPackage(
            IntPtr LsaHandle,
            int AuthenticationPackage,
            IntPtr ProtocolSubmitBuffer,
            int SubmitBufferLength,
            out IntPtr ProtocolReturnBuffer,
            out int ReturnBufferLength,
            out int ProtocolStatus
        );

        [DllImport("secur32.dll", SetLastError = false)]
        public static extern int LsaDeregisterLogonProcess(
            [In] IntPtr LsaHandle
        );

        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll")]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(
            IntPtr hObject
        );
    }
}