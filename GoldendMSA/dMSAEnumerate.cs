using System;
using System.Net;
using System.DirectoryServices.Protocols;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.DirectoryServices.ActiveDirectory;
using System.Management;
using AuthenticationLevel = System.Management.AuthenticationLevel;

namespace GoldendMSA {
    public class dMSAEnumerate
    {
        public static void PrintDMSAs(String DomainName, string user, string password, string userDomain, int maxRid)
        {
            try
            {
                try
                {
                    var lsaLookup = new LSALookupSid(
                    username: user,
                    password: password,
                    domain: userDomain,
                    port: 445,
                    maxRid: maxRid
                    );

                    (string dcFqdn, string dcIp) = LdapUtils.GetDomainControllerInfoAlt(DomainName);


                    lsaLookup.Dump(dcFqdn, dcIp);
                }
                catch {
                    var lsaLookup = new LSALookupSid(
                        username: user,
                        password: password,
                        domain: userDomain,
                        port: 139,
                        maxRid: maxRid
                        );

                    (string dcFqdn, string dcIp) = LdapUtils.GetDomainControllerInfoAlt(DomainName);

                    
                    lsaLookup.Dump(dcFqdn, dcIp);
                
                }
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Critical Error: {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}");

                // Common TLS/SSL troubleshooting tips
                Console.WriteLine("\nTroubleshooting Tips:");
                Console.WriteLine("1. Ensure target server is reachable");
                Console.WriteLine("2. Check firewall settings (ports 139, 445)");
                Console.WriteLine("3. Verify credentials are correct");
            }
        }


    }


    public class LSALookupSid
    {
        private readonly string _username;
        private readonly string _password;
        private readonly int _port;
        private readonly int _maxRid;
        private readonly string _domain;
        private readonly string _lmHash;
        private readonly string _ntHash;
        private readonly bool _domainSids;
        private readonly bool _useKerberos;

        public LSALookupSid(string username = "", string password = "", string domain = "",
                           int? port = null, string hashes = null, bool domainSids = false,
                           bool useKerberos = false, int maxRid = 4000)
        {
            // Configure TLS/SSL settings to bypass certificate validation
            ServicePointManager.ServerCertificateValidationCallback = AcceptAllCertificates;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            ServicePointManager.CheckCertificateRevocationList = false;

            _username = username;
            _password = password;
            _port = port ?? 445;
            _maxRid = maxRid;
            _domain = domain;
            _domainSids = domainSids;
            _useKerberos = useKerberos;

            if (!string.IsNullOrEmpty(hashes))
            {
                var hashParts = hashes.Split(':');
                _lmHash = hashParts.Length > 0 ? hashParts[0] : "";
                _ntHash = hashParts.Length > 1 ? hashParts[1] : "";
            }
            else
            {
                _lmHash = "";
                _ntHash = "";
            }
        }

        // Accept all SSL certificates (for testing purposes)
        private static bool AcceptAllCertificates(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        public void Dump(string remoteName, string remoteHost)
        {
            Console.WriteLine($"Brute forcing SIDs at {remoteName}");

            try
            {
                BruteForce(remoteName, remoteHost, _maxRid);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Critical error: {e.Message}");
                throw;
            }
        }

        private void BruteForce(string remoteName, string remoteHost, int maxRid)
        {
            string domainSid = GetDomainSid(remoteName);
            Console.WriteLine($"Domain SID is: {domainSid}");
            Console.WriteLine("");
            List<String> specialAccounts = LdapUtils.SearchForGMSAsDirectly(remoteName, true, _domain,_username,_password);

            int soFar = 0;
            const int SIMULTANEOUS = 1000;

            for (int j = 0; j <= maxRid / SIMULTANEOUS; j++)
            {
                int sidsToCheck;
                if ((maxRid - soFar) / SIMULTANEOUS == 0)
                {
                    sidsToCheck = (maxRid - soFar) % SIMULTANEOUS;
                }
                else
                {
                    sidsToCheck = SIMULTANEOUS;
                }

                if (sidsToCheck == 0)
                    break;

                var sids = new List<string>();
                for (int i = soFar; i < soFar + sidsToCheck; i++)
                {
                    sids.Add($"{domainSid}-{i}");
                }

                try
                {
                    LookupSids(sids, soFar, specialAccounts);
                }
                catch (Exception e)
                {
                    if (e.Message.Contains("STATUS_NONE_MAPPED"))
                    {
                        soFar += SIMULTANEOUS;
                        continue;
                    }
                    else if (e.Message.Contains("STATUS_SOME_NOT_MAPPED"))
                    {
                        // Handle partial results
                        ProcessPartialResults(sids, soFar, specialAccounts);
                    }
                    else
                    {
                        throw;
                    }
                }

                soFar += SIMULTANEOUS;
            }
        }

        private string GetDomainSid(string remoteName)
        {
            try
            {
                Console.WriteLine($"Attempting to connect to {remoteName}...");

                // Try multiple connection methods
                return TryGetDomainSidMultipleMethods(remoteName);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error getting domain SID: {e.Message}");
                Console.WriteLine($"Stack trace: {e.StackTrace}");
            }

            // Fallback: construct a typical domain SID pattern
            Console.WriteLine("Using fallback domain SID");
            return "S-1-5-21-1234567890-1234567890-1234567890";
        }

        private string TryGetDomainSidMultipleMethods(string remoteName)
        {
            // Method 1: Try with explicit credentials if provided
            if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
            {
                try
                {
                    Console.WriteLine("Trying connection with explicit credentials...");
                    using (var context = new PrincipalContext(
                        ContextType.Domain,
                        remoteName,
                        _username,
                        _password))
                    {
                        return GetSidFromContext(context, remoteName);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Method 1 failed: {ex.Message}");
                }
            }

            // Method 2: Try without explicit credentials (current user context)
            try
            {
                Console.WriteLine("Trying connection with current user context...");
                using (var context = new PrincipalContext(ContextType.Domain, remoteName))
                {
                    return GetSidFromContext(context, remoteName);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Method 2 failed: {ex.Message}");
            }

            // Method 3: Try using DirectoryEntry with LDAP
            try
            {
                Console.WriteLine("Trying LDAP connection...");
                return GetSidViaLDAP(remoteName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Method 3 failed: {ex.Message}");
            }

            throw new Exception("All connection methods failed");
        }



        private string GetSidFromContext(PrincipalContext context, string remoteName)
        {
            try
            {
                // Method 1: Try to get domain SID by finding any domain user
                using (var searcher = new PrincipalSearcher(new UserPrincipal(context)))
                {
                    var searchResults = searcher.FindAll();
                    foreach (Principal principal in searchResults.Take(10)) // Check first 10 users
                    {
                        if (principal?.Sid != null)
                        {
                            string sidString = principal.Sid.ToString();
                            if (sidString.StartsWith("S-1-5-21-"))
                            {
                                var parts = sidString.Split('-');
                                if (parts.Length >= 7) // Domain SID should have at least 7 parts
                                {
                                    // Domain SID is everything except the last part (RID)
                                    return string.Join("-", parts.Take(parts.Length - 1));
                                }
                            }
                        }
                    }
                    searchResults.Dispose();
                }

                // Method 2: Try to get the domain SID using DirectoryEntry from the context
                DirectoryEntry domainEntry = null;
                try
                {
                    // Get the DirectoryEntry for the domain
                    if (context.ConnectedServer != null)
                    {
                        string ldapPath = $"LDAP://{context.ConnectedServer}";

                        if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
                        {
                            domainEntry = new DirectoryEntry(ldapPath, $"{_domain}\\{_username}", _password, AuthenticationTypes.Secure);
                        }
                        else
                        {
                            domainEntry = new DirectoryEntry(ldapPath);
                        }

                        var objectSid = domainEntry.Properties["objectSid"].Value as byte[];
                        if (objectSid != null)
                        {
                            var sid = new SecurityIdentifier(objectSid, 0);
                            return sid.ToString();
                        }
                    }
                }
                finally
                {
                    domainEntry?.Dispose();
                }

                // Method 3: Try to find Domain Admins group (well-known RID 512)
                try
                {
                    using (var groupSearcher = new PrincipalSearcher(new GroupPrincipal(context)))
                    {
                        var groups = groupSearcher.FindAll();
                        foreach (GroupPrincipal group in groups.Cast<GroupPrincipal>().Take(20))
                        {
                            if (group.Name?.ToLower().Contains("domain admins") == true ||
                                group.Name?.ToLower().Contains("administrators") == true)
                            {
                                if (group.Sid != null)
                                {
                                    string sidString = group.Sid.ToString();
                                    if (sidString.StartsWith("S-1-5-21-") && sidString.EndsWith("-512"))
                                    {
                                        // Remove the -512 to get domain SID
                                        return sidString.Substring(0, sidString.LastIndexOf('-'));
                                    }
                                }
                            }
                        }
                        groups.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Group search method failed: {ex.Message}");
                }

                throw new Exception("Could not retrieve domain SID from context using any method");
            }
            catch (Exception ex)
            {
                throw new Exception($"GetSidFromContext failed: {ex.Message}");
            }
        }


        private string GetSidViaLDAP(string remoteName)
        {
            string ldapPath = $"LDAP://{remoteName}";

            DirectoryEntry entry;
            if (!string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password))
            {
                entry = new DirectoryEntry(ldapPath, _username, _password, AuthenticationTypes.Secure);
            }
            else
            {
                entry = new DirectoryEntry(ldapPath);
            }

            using (entry)
            {
                var objectSid = entry.Properties["objectSid"].Value as byte[];
                if (objectSid != null)
                {
                    var sid = new SecurityIdentifier(objectSid, 0);
                    return sid.ToString();
                }
            }

            throw new Exception("Could not retrieve SID via LDAP");
        }


        private void LookupSids(List<string> sids, int baseIndex, List<String> specialAccounts)
        {
            foreach (var sidString in sids.Select((sid, index) => new { sid, index }))
            {
                try
                {
                    var sid = new SecurityIdentifier(sidString.sid);

                    // Try to translate the SID to an account name
                    try
                    {
                        var account = (NTAccount)sid.Translate(typeof(NTAccount));
                        string [] justName = (account.Value).Split('\\');
                        if (justName[1] != null)
                        {
                            if ((justName[1]).EndsWith("$"))
                            {
                                
                                if (!specialAccounts.Contains(justName[1]))
                                {
                                    Console.WriteLine($"{sidString.sid}: {account.Value} (Suspected DMSA - Regular resolve)");
                                }
                            }
                        }

                    }
                    catch (IdentityNotMappedException)
                    {
                        // Try alternative resolution methods
                        string resolvedName = TryAlternativeSidResolution(sidString.sid);
                        if (!string.IsNullOrEmpty(resolvedName))
                        {
                            if (resolvedName.EndsWith("$"))
                            {
                                if (!specialAccounts.Contains(resolvedName))
                                {
                                    Console.WriteLine($"{sidString.sid}: {resolvedName} (Suspected DMSA - Alternative resolve)");
                                }
                            }
                        }
                    }
                }
                catch (ArgumentException ex)
                {
                    Console.WriteLine($"Invalid SID format {sidString.sid}: {ex.Message}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error looking up SID {sidString.sid}: {e.Message}");
                }
            }
        }

        private string TryAlternativeSidResolution(string sidString)
        {
            try
            {
                // Method 1: Try using DirectorySearcher
                if (!string.IsNullOrEmpty(_domain))
                {
                    using (var searcher = new DirectorySearcher())
                    {
                        searcher.Filter = $"(objectSid={ConvertSidToSearchFormat(sidString)})";
                        searcher.PropertiesToLoad.Add("sAMAccountName");
                        searcher.PropertiesToLoad.Add("name");

                        var result = searcher.FindOne();
                        if (result != null)
                        {
                            string name = result.Properties["sAMAccountName"][0]?.ToString() ??
                                         result.Properties["name"][0]?.ToString();
                            return name;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Alternative resolution failed: {ex.Message}");
            }

            return null;
        }

        private string ConvertSidToSearchFormat(string sid)
        {
            try
            {
                // Convert SID string to binary format for LDAP search
                var securityIdentifier = new SecurityIdentifier(sid);
                byte[] sidBytes = new byte[securityIdentifier.BinaryLength];
                securityIdentifier.GetBinaryForm(sidBytes, 0);
                return "\\" + string.Join("\\", sidBytes.Select(b => b.ToString("X2")));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error converting SID to search format: {ex.Message}");
                return sid; // Return original SID as fallback
            }
        }

        private void ProcessPartialResults(List<string> sids, int baseIndex, List<String> specialAccounts)
        {
            // Process partial results when some SIDs are mapped and others aren't
            LookupSids(sids, baseIndex, specialAccounts);
        }

        // Alternative implementation using P/Invoke for direct LSA calls

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint LsaLookupSids(
            IntPtr PolicyHandle,
            int Count,
            IntPtr[] Sids,
            out IntPtr ReferencedDomains,
            out IntPtr Names);

        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr PolicyHandle);

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }


    }
}

