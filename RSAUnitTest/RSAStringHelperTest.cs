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
            RSAStringKeyPair pair = RSAStringHelper.GenKeyPair(1024);

            String textSigned = RSAStringHelper.SignToBase64("hello world", pair.PrivateKey, "MD5"); 
            bool result = RSAStringHelper
                    .VerifyFromBase64("hello world", pair.PublicKey, textSigned, "MD5");

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void sign()
        {
            RSAStringKeyPair pair =  RSAStringHelper.GenKeyPair(1024);
            var privateKey = pair.PrivateKey;
            var publicKey = pair.PublicKey;
            
            String textSigned = RSAStringHelper.SignToBase64("hello world", privateKey, "SHA1");
        }

        [TestMethod]
        public void verify()
        {
            string text = "123456";
            string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMagLZkMaJZjx8PJOLQCtQqm/quBSO4b0FjlQYm+iGM+cEwzRMaGC3a0/nwXd1mfrUau83AIZQF5bvl0mBV1RsrZpMpOIn6OErThObsfu8vYPy7rIiUNNiIqIwtdifh7+BoLNzO1WejuKzOnPMPEUb6mv106m4xniOOWhn4Av4YQIDAQAB";
            string signBase64 = "cYCX+McctQgYq4q1bpGMXCcw3RGyvGNJAk+sFmxb5coCLmAcEymGka0mMQHXyuBf/ViEpsek23gmSU41imQqc9IRJCk2swcY+VsDUA8F4pa7jNpXoqzAgblr1lFvMx/mAVqlxijZ4b2046h75U/jC/HGlIUDsgNF5oA3sd4l0fM=";

            Assert.IsTrue(RSAStringHelper.VerifyFromBase64(text, publicKey, signBase64, "MD5"));
        }

        [TestMethod]
        public void encrypt()
        {
            RSAStringKeyPair pair = RSAStringHelper.GenKeyPair(1024);
            var privateKey = pair.PrivateKey;
            var publicKey = pair.PublicKey;

            string text = "andon";

            string result = RSAStringHelper.Encrypt(text, publicKey);
        }

        [TestMethod]
        public void decrypt()
        {
            string text = "Zyt4TEpN+U+zoCSm8WRzLq2r418fPnko+yjLwobbb+2cm9i+WJJa4oqIzd44yijyMbJJe/aEd9WIndhJiB9ritk3Cepq2Q9mbCcMrpfCdTax2UfDXZOWuEi7bRsIahhX2PtLSlbXaffBzZ137Nx0XkIeGfoUfctRlccipavChqk=";
            string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAK23i8dl0FdDLsn27gHrXij27rarT5IgHFehehX6mHKwX+WS5ymvneMkaBr9vmsTBzstewQgOemDsCz+PDYUNRls92KZH3mawYoArW0e8qwOS7a+lsO8SAIM2KdQN4aYS5kZGTcSK1/QLp6Ajltt8fkuEKeibzgzDNiZEWF8WkvVAgMBAAECgYByQSZOH0jIHAfKDf68hHGJv9+BhWrwUO5TNIF3szpRNG/eLqCbakYN/wP5vKphAkLfSSp/rDJqw5I8BXrUlrXUzcJFtasDA4VeW8yYJ6+W+NmzPtHr5Ax801dMDqjAVUfV5j7bjxJHCQM6am3+YM3ztWNxFptSBi1KpGo0LxgYgQJBANcDR+KqZigzs4clh+fQTJmxz/TGXEHcs7Nip9wHPKNT8t5ZgE48HjbF7cgKa8A4WwTD8dZkEev51P/xgCbSFw8CQQDO1QKfvejKHkQgtiZIYgxaRmWY8KZBQj/oEgi7JPyeEKt3od10B9Tq4VpbJmDcmDylE3dOJ8vN0z8rVzqyxk7bAkAItrlTFlTNjEraT0sSuf5gvDQRV3ilsqwVuQnUgPaUJ/LP0BDDGuyei6b3VHTJdX860jYa2jNfvOBE/ySSbjFBAkAd2iq1yaA2w+WLXx7pZZVo1i5Fw74LPzegFDJEaJM5cSh+bNNcsuCtQfdbno9uZ16haMzYb+//dhTw+XcUZIDvAkEAitv/JsGySgOPKff3SMD+yD6sp9D40PcGKzzi1ZD8KdHQ8CkDDmBtRgIYUdgHynGjcZU2QVcfJs4MIs0BY+983w==";

            string result = RSAStringHelper.Decrypt(text, privateKey);

            Assert.AreEqual("hello world", result);
        }

    }
}
