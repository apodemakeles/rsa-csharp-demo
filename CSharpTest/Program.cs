using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CSharpTest
{
    class Program
    {
        static void Main(string[] args)
        {
            //string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvhr835o+eNU4b149b4Lg0bzM9KXug0+CeefnpmYYzwuVnf4aPS/OXmIRxajcCVlpxYgIcbQq2F0jbyJi1mcnyK4tROnrPv4a5+ImW6j8C2w9EKnVFDKNc9mYhN5NfZIk+7oK4YKlxI7hodZbuRqh65P1UI21ZfvYEP8ahICN23wIDAQAB";
            string privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKvJDdlcTIKxsnLXaXujwaTbz/U3ftO4evDeIsvTNmTi/UAZra3j5dRBLnw8h99kTrD+Pulew4ZA2C8cFkPwuePP2YsfNJ+hk0uauir1hqYL02JDasrp0HTq01UdbkHQjj6lqTSXpK1JnbNl8hkmJYuQAtLhtPDWd5WSZCPBHa/BAgMBAAECgYBmPg3OFs864kRRccBIZFi2pFWLn3IO1Tfm8G9JXPZ86VTNt/rVClUaFYlzTBuaa/siANC02UAKQcHpmA/wc/BOllPK0Uc/Qv6Blj4biy8ZA1h3ldG3P2UPdFt8bnR4XvwOxS2O2rvrUe2gSlvUXmmAto1X84H9/xDYGYdOXMy6oQJBAP8MU6Z2oQ+UadIfpAhj1B/s7JyRRxl43jIKbm7Pxxsh48jGTrXnMqbUTjUnpIigfZgptwGyOORlf8nhW9HtfX0CQQCsbS2RRksOFDipMdWBGnG3faQQZuPZ0TXeFU2vBSJBQPLAPioElcj8seKE/pnhA/N+BglZMSLP4nFIj4pVGx6VAkEAtmYFaNYMB01XhItWTx29tXtGGA6Zr3DOTzFAmwUDWrcY5RxVbCfFBKRurfsE4yULzQeANrlTkJu6ERGXDgHvLQJBAJhs/35QZKMyjxBLJJG3ndV2tSVmv3/baUJFFOJmqGyFDNOTYLOi8gUo/7VQGRoI0ySSE4uMW1jotfpOIhywF60CQQDAnT5yEGxSx65Nn/5XcFsk/p8PoX1ehJrfEOo0i+egYa1eaXJRQVSinR66XGYE0OA/E2XEfXVWuES8hpVgGEoE";

            //SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
            //MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            //byte[] hashed = md5.ComputeHash(Encoding.UTF8.GetBytes("8f8c733bf4ab4a039d85d7d1d470759b"));
            
            //byte[] result = RSAUtils.EncryptByPrivateKey(hashed, Convert.FromBase64String(privateKey));

            //Console.WriteLine(Convert.ToBase64String(result));


            //var pair = RSAUtils.GenKeyPEM(1024);

            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            byte[] hashed = md5.ComputeHash(Encoding.UTF8.GetBytes("8f8c733bf4ab4a039d85d7d1d470759b"));
            byte[] result = RSAUtils.EncryptByPrivateKey(hashed, Convert.FromBase64String(privateKey));
            Console.WriteLine(Convert.ToBase64String(result));


            Console.ReadLine();
        }
    }
}
