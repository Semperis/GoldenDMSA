using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace GoldendMSA
{
    public class LdapEnumeration
    {
        private static bool ServerCallback(LdapConnection connection, X509Certificate certificate)
        {
            return true;
        }

        private static bool AcceptAllCertificates(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Accept all certificates for testing purposes
            return true;
        }

        public static int ldapEnumeration(String DomainName)
        {
            (string dcName, string dcIp) = LdapUtils.GetDomainControllerInfoAlt(DomainName);

            List<String> SpecialAccounts = LdapUtils.SearchForGMSAsDirectly(dcName, false, DomainName);
            string baseDN = "CN=Managed Service Accounts,DC=" + DomainName.Replace(".",",DC=");
            string domainName = (DomainName.Split('.'))[0];
            string accountSam = "*";
            string filter = $"(&(objectClass=*)(sAMAccountName={accountSam}))";

            ServicePointManager.ServerCertificateValidationCallback = AcceptAllCertificates;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
            ServicePointManager.CheckCertificateRevocationList = false;

            LdapConnection connection = null;
            try
            {
                // Create LDAP connection
                var ldapDirectoryIdentifier = new LdapDirectoryIdentifier(dcName, 389);
                connection = new LdapConnection(ldapDirectoryIdentifier);

                // Set protocol version to LDAPv3
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;

                // Configure TLS with error handling
                try
                {
                    connection.SessionOptions.VerifyServerCertificate = new VerifyServerCertificateCallback(ServerCallback);

                    connection.SessionOptions.SecureSocketLayer = false;
                    connection.SessionOptions.StartTransportLayerSecurity(null);
                }
                catch (TlsOperationException tlsEx)
                {
                    connection.Dispose();
                    connection = new LdapConnection(ldapDirectoryIdentifier);
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
                }

                connection.AuthType = AuthType.Negotiate;
                connection.Credential = CredentialCache.DefaultNetworkCredentials;

                // Bind to the directory
                connection.Bind();

                // Perform LDAP search
                var searchRequest = new SearchRequest(
                    baseDN,
                    "(objectclass=*)",
                    SearchScope.OneLevel,
                    null // Return all attributes
                );

                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                if (searchResponse.ResultCode != ResultCode.Success)
                {
                    Console.WriteLine($"ldap_search_s failed: {searchResponse.ResultCode} - {searchResponse.ErrorMessage}");
                    return 1;
                }

                int count = 0;

                // Process search results
                foreach (SearchResultEntry entry in searchResponse.Entries)
                {
                    if ((!SpecialAccounts.Contains(entry.DistinguishedName)))
                    {
                        Console.WriteLine($"\nEntry DN: {entry.DistinguishedName}");
                        string accountName = "";

                        string adsPath = entry.DistinguishedName;

                        adsPath = "LDAP://" + adsPath;
                        if (adsPath.StartsWith("LDAP://CN="))
                        {
                            int startIndex = "LDAP://CN=".Length;
                            int endIndex = adsPath.IndexOf(',', startIndex);
                            if (endIndex > startIndex)
                            {
                                accountName = adsPath.Substring(startIndex, endIndex - startIndex);
                                Console.WriteLine($"Account Name (from ADSPath):\t{accountName}$");
                            }
                        }
                        if (!string.IsNullOrEmpty(accountName))
                        {
                            try
                            {
                                // Try to resolve SID using NTAccount
                                string domainAccount = accountName.Contains("\\") ? accountName : $"{domainName}\\{accountName}$";
                                NTAccount ntAccount = new NTAccount(domainAccount);
                                SecurityIdentifier sid = (SecurityIdentifier)ntAccount.Translate(typeof(SecurityIdentifier));
                                Console.WriteLine($"SID :\t{sid.Value}");
                            }
                            catch (Exception resolveEx)
                            {
                                Console.WriteLine($"SID : Failed to resolve - {resolveEx.Message}");
                            }
                        }
                        // Look for objectClass attribute specifically
                        if (entry.Attributes.Contains("objectClass"))
                        {
                            var objectClassAttribute = entry.Attributes["objectClass"];
                            foreach (string value in objectClassAttribute.GetValues(typeof(string)))
                            {
                                Console.WriteLine($"    objectClass: {value}");
                            }
                        }
                        if (entry.Attributes.Contains("objectSid"))
                        {
                            var objectSidAttribute = entry.Attributes["objectSid"];
                            string sidValue = new System.Security.Principal.SecurityIdentifier((byte[])objectSidAttribute.GetValues(typeof(byte[]))[0], 0).Value;

                            Console.WriteLine($"    objectSid: {sidValue}");
                        }
                        if (entry.Attributes.Contains("msDS-ManagedPasswordId"))
                        {
                            DirectoryAttribute da = entry.Attributes["msDS-ManagedPasswordId"];
                            byte[] objectPassAttribute = (byte[])(da.GetValues(typeof(byte[]))[0]);
                            MsdsManagedPasswordId mpid = new MsdsManagedPasswordId(objectPassAttribute);
                            Console.WriteLine("Related key: " + mpid.RootKeyIdentifier);
                            Console.WriteLine($"    msDS-ManagedPasswordId: {Convert.ToBase64String(objectPassAttribute)}");
                        }

                        count++;
                    }
                }

                if (count == 0)
                {
                    Console.WriteLine("No matching entries found.");
                }
                else
                {
                    Console.WriteLine($"\nTotal entries found: {count}");
                }

                return 0;
            }
            catch (LdapException ex)
            {
                Console.WriteLine($"LDAP Error: {ex.ErrorCode} - {ex.Message}");
                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return 1;
            }
            finally
            {
                connection?.Dispose();
            }
        }
    }
}
