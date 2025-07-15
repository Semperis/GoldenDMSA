using System;
using System.ComponentModel;
using System.Runtime.InteropServices;


namespace GoldendMSA {
    public class LSA
    {
        public static IntPtr GetLsaHandle(bool elevateToSystem = true)
        {
            IntPtr lsaHandle = IntPtr.Zero;

            if (Helpers.IsHighIntegrity() && elevateToSystem && !Helpers.IsSystem())
            {
                if (!Helpers.GetSystem())
                {
                    throw new Exception("Could not elevate to system");
                }

                Interop.LsaConnectUntrusted(out lsaHandle);
                Interop.RevertToSelf();
            
            } else {
                Interop.LsaConnectUntrusted(out lsaHandle);
            }

            return lsaHandle;
        }

        public static void ImportTicket(byte[] ticket, LUID targetLuid)
        {

            var lsaHandle = GetLsaHandle();
            int AuthenticationPackage;
            int ntstatus, ProtocalStatus;

            if ((ulong)targetLuid != 0)
            {
                if (!Helpers.IsHighIntegrity())
                {
                    Console.WriteLine("[X] You need to be in high integrity to apply a ticket to a different logon session");
                    return;
                }
            }

            var inputBuffer = IntPtr.Zero;
            IntPtr ProtocolReturnBuffer;
            int ReturnBufferLength;
            try
            {
                Interop.LSA_STRING_IN LSAString;
                var Name = "kerberos";
                LSAString.Length = (ushort)Name.Length;
                LSAString.MaximumLength = (ushort)(Name.Length + 1);
                LSAString.Buffer = Name;
                ntstatus = Interop.LsaLookupAuthenticationPackage(lsaHandle, ref LSAString, out AuthenticationPackage);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                var request = new Interop.KERB_SUBMIT_TKT_REQUEST();
                request.MessageType = Interop.KERB_PROTOCOL_MESSAGE_TYPE.KerbSubmitTicketMessage;
                request.KerbCredSize = ticket.Length;
                request.KerbCredOffset = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST));

                if ((ulong)targetLuid != 0)
                {
                    Console.WriteLine("[*] Target LUID: 0x{0:x}", (ulong)targetLuid);
                    request.LogonId = targetLuid;
                }

                var inputBufferSize = Marshal.SizeOf(typeof(Interop.KERB_SUBMIT_TKT_REQUEST)) + ticket.Length;
                inputBuffer = Marshal.AllocHGlobal(inputBufferSize);
                Marshal.StructureToPtr(request, inputBuffer, false);
                Marshal.Copy(ticket, 0, new IntPtr(inputBuffer.ToInt64() + request.KerbCredOffset), ticket.Length);
                ntstatus = Interop.LsaCallAuthenticationPackage(lsaHandle, AuthenticationPackage, inputBuffer, inputBufferSize, out ProtocolReturnBuffer, out ReturnBufferLength, out ProtocalStatus);
                if (ntstatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ntstatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage: {1}", winError, errorMessage);
                    return;
                }
                if (ProtocalStatus != 0)
                {
                    var winError = Interop.LsaNtStatusToWinError((uint)ProtocalStatus);
                    var errorMessage = new Win32Exception((int)winError).Message;
                    Console.WriteLine("[X] Error {0} running LsaLookupAuthenticationPackage (ProtocalStatus): {1}", winError, errorMessage);
                    return;
                }
                Console.WriteLine("[+] Ticket successfully imported!");
            }
            finally
            {
                if (inputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(inputBuffer);

                Interop.LsaDeregisterLogonProcess(lsaHandle);
            }
        }
    }
}
