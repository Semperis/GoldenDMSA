using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;


namespace GoldendMSA
{
    public static class LdapUtils
    {
        public static SearchResultCollection FindInConfigPartition(string domainFqdn, string ldapFilter, string[] attributes)
        {
            using (var de = GetConfigNamingContextDe(domainFqdn))
            using (var ds = new DirectorySearcher(de, ldapFilter, attributes))
            {
                ds.PageSize = 100;
                SearchResultCollection results = ds.FindAll();
                if (results == null)
                {
                    throw new Exception($"Could not find any results using LDAP filter: {ldapFilter}");
                }
                return results;
            }
        }
        public static SearchResultCollection FindInDomain(string domainFqdn, string ldapFilter, string[] attributes)
        {
            using (var de = GetDefaultNamingContextDe(domainFqdn))
            using (var ds = new DirectorySearcher(de, ldapFilter, attributes))
            {
                ds.PageSize = 100;
                SearchResultCollection results = ds.FindAll();
                if (results == null)
                {
                    throw new Exception($"Could not find any results using LDAP filter: {ldapFilter}");
                }
                return results;
            }
        }

        private static DirectoryEntry GetDefaultNamingContextDe(string domainName)
        {
            using (var rootDse = GetRootDse(domainName))
            {
                string adsPAth = $"LDAP://{domainName}/{rootDse.Properties["defaultNamingContext"].Value}";
                return new DirectoryEntry(adsPAth);
            }
        }

        private static DirectoryEntry GetConfigNamingContextDe(string domainName)
        {
            using (var rootDse = GetRootDse(domainName))
            {
                string adsPAth = $"LDAP://{domainName}/{rootDse.Properties["configurationNamingContext"].Value}";
                return new DirectoryEntry(adsPAth);
            }
        }

        public static (string fqdn, string ip) GetDomainControllerInfoAlt(string domainName)
        {
            try
            {
                // Get domain context
                var context = new DirectoryContext(DirectoryContextType.Domain, domainName);
                var domain = Domain.GetDomain(context);
                // Get primary domain controller
                var dc = domain.PdcRoleOwner;
                var dcFqdn = dc.Name;

                // Resolve IP address
                var ipAddresses = Dns.GetHostAddresses(dcFqdn);
                var dcIp = ipAddresses.FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.ToString();

                if (string.IsNullOrEmpty(dcIp))
                {
                    throw new Exception($"Could not resolve IP address for {dcFqdn}");
                }

                return (dcFqdn, dcIp);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to get domain controller using DirectoryServices: {ex.Message}");
            }
        }

        public static DirectoryEntry GetRootDse(string domainName)
        {
            return new DirectoryEntry($"LDAP://{domainName}/RootDSE");
        }

        private static String ExtractGMSAInfo(SearchResult result, bool samaccountname)
        {

            if (samaccountname)
            {
                return result.Properties["sAMAccountName"][0]?.ToString();
            }
            return Uri.UnescapeDataString(new Uri(result.Properties["adsPath"][0]?.ToString()).AbsolutePath.TrimStart('/'));

        }

        public static List<String> SearchForGMSAsDirectly(string remoteName, bool attribute,string domain, string username = "", string password = "")
        {
            List<string> gmsaList = new List<string>();

            try
            {
                string ldapPath = $"LDAP://{remoteName}";
                DirectoryEntry rootEntry;

                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    rootEntry = new DirectoryEntry(ldapPath, $"{domain}\\{username}", password,
                                                 AuthenticationTypes.Secure);
                }
                else
                {
                    rootEntry = new DirectoryEntry(ldapPath);
                }

                using (rootEntry)
                using (var searcher = new DirectorySearcher(rootEntry))
                {
                    // Direct LDAP filter for GMSAs
                    searcher.Filter = "(&(|(objectClass=msDS-GroupManagedServiceAccount)(&(sAMAccountName=*$)(objectCategory=person)(objectClass=user))(objectCategory=msDS-ManagedServiceAccount)(objectClass=trustedDomain)(objectClass=computer))(!(objectClass=msDS-DelegatedManagedServiceAccount)))";
                    searcher.PropertiesToLoad.AddRange(new[] {
                        "sAMAccountName"
                    });

                    var results = searcher.FindAll();

                    foreach (SearchResult result in results)
                    {
                        try
                        {
                            string gmsa = ExtractGMSAInfo(result, attribute);
                            gmsaList.Add(gmsa);
                        }
                        catch (Exception ex)
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[X] Error during direct GMSA search: {ex.Message}");
            }
            return gmsaList;
        }
    }
}