using CSharpTest;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSAUnitTest
{
    [TestClass]
    public class RSAStringHelperTest
    {
        [TestMethod]
        public void generate_key_pair()
        {
            var pair = RSAStringHelper.GenKeyPair(1024);
            Assert.IsNotNull(pair.PrivateKey);
            Assert.IsNotNull(pair.PublicKey);
        }

        [TestMethod]
        public void encrpyt_then_decrypt()
        {
            var pair = RSAStringHelper.GenKeyPair(1024);

            var textEncrpyted = RSAStringHelper.Encrypt("hello world", pair.PublicKey);
            var text = RSAStringHelper.Decrypt(textEncrpyted, pair.PrivateKey);

            Assert.AreEqual("hello world", text);

        }

        [TestMethod]
        public void sign_then_verify()
        {
            var pair = RSAStringHelper.GenKeyPair(1024);

            var textSigned = RSAStringHelper.EncryptByPrivateKey("hello world", pair.PrivateKey);
            var text = RSAStringHelper.DecryptByPublicKey(textSigned, pair.PublicKey);

            Assert.AreEqual("hello world", text);
        }

        [TestMethod]
        public void sign()
        {
            var publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCAZ99PI8xQAjg23R7GA3KWI9xrFXBPFyR9y3Cs3KGF/JuJBp0MRvNu6vszCp104savWup5/u/PsmiX0aOKkKkcQz8fN4/jAwFaW7NCvVbICYCAedFgcmnUDa+RXkwO6X7HceENB/EH7AmiF+cTF7d8UzuXrlDrW7t4Eak9nOo34QIDAQAB";
            var privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIBn308jzFACODbdHsYDcpYj3GsVcE8XJH3LcKzcoYX8m4kGnQxG827q+zMKnXTixq9a6nn+78+yaJfRo4qQqRxDPx83j+MDAVpbs0K9VsgJgIB50WByadQNr5FeTA7pfsdx4Q0H8QfsCaIX5xMXt3xTO5euUOtbu3gRqT2c6jfhAgMBAAECgYARZQDdSa4t0H8o/39ht6nYKPd9EiRqsmnhGKQk5qaC7htrzpeLyDjF99MbsP5vjSD5NEm7SQvXiQWeO2n6JWqjFjWmEjmSakdlOSFmMeru/gQ4o3sOz6zjiRESJ5/dskautqmDA3GD9IozYJ/ylc/jiRnhJmWc6mBsp20qaPCGoQJBAMUiy3NW8fuU33/QMHyL1UgJ6yjbrh6nmRqlBTd04J+bEwZZG2el8EvFsi1f+0WRm/QMYMNEzIZqbXR8eeozx/0CQQCmv0veh9EGrfNRWBrAGNXHFHdzkiYNECqDuCiXlghWVd02S2YmppNFMu09TfbXGA3nME2TIqG+9ZqQb1IzALq1AkBmmaZjwEOvGZt9DSC/IZP+q1Ld7//eaoIP0QU3CLiDuRUcv7G4ry+ycBE89nBzk8YkLXELEDqWVrvi3YoiL5MNAkAHwfScqMLvxZ4BVdEAyOcBORGJne4JQ4xGzoWM79z5b0s4YG+jMrK9UG47IOpv/V2AOP4S71SJFtIXECbJ2qnVAkAOaYHCssdYskO364IIQNnvTGgV0ft//WdRoSPrageEwTlLX3JKW/YemB31v2DMXwpTEeh+rDZPskrYULXvf58K";

            SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
            byte[] hashed = sha1.ComputeHash(Encoding.UTF8.GetBytes("hello world"));
            byte[] result = RSAUtils.EncryptByPrivateKey(hashed, Convert.FromBase64String(privateKey));

            Console.WriteLine(Convert.ToBase64String(result));
        }
    }
}
