using CSharpTest;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
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

            var textEncrpyted = RSAStringHelper.EncrpytByPublicKey("hello world", pair.PublicKey);
            var text = RSAStringHelper.DecryptByPrivateKey(textEncrpyted, pair.PrivateKey);

            Assert.AreEqual("hello world", text);

        }

        [TestMethod]
        public void sign_then_verify()
        {
            var pair = RSAStringHelper.GenKeyPair(1024);

            var textSigned = RSAStringHelper.EncrpytByPrivateKey("hello world", pair.PrivateKey);
            var text = RSAStringHelper.DecryptByPublicKey(textSigned, pair.PublicKey);

            Assert.AreEqual("hello world", text);
        }
    }
}
