using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace CSharpTest
{
    public class RSAStringHelper
    {
        /// <summary>
        /// 产生密钥对
        /// </summary>
        /// <param name="keysize">密钥长度，一般为256, 1024, 2048</param>
        /// <returns></returns>
        public static RSAStringKeyPair GenKeyPair(int keysize)
        {
            RSAKeyPair pair = RSAUtils.GenKeyPair(keysize);

            return new RSAStringKeyPair(Convert.ToBase64String(pair.PrivateKey), Convert.ToBase64String(pair.PublicKey));
        }

        private static AsymmetricKeyParameter GetPublicKey(string s) 
        {
            return PublicKeyFactory.CreateKey(Convert.FromBase64String(s));
        }

        private static AsymmetricKeyParameter GetPrivateKey(string s)
        {
            return PrivateKeyFactory.CreateKey(Convert.FromBase64String(s));
        }

        


        /// <summary>
        /// 通过公钥加密，一般用作信息解密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="publicKey">公钥Base64</param>
        /// <returns>加密结果Base64</returns>
        public static string EncrpytByPublicKey(string data, string publicKey)      
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(true, GetPublicKey(publicKey));
            var bytes = Encoding.UTF8.GetBytes(data);
            var result = engine.ProcessBlock(bytes, 0, bytes.Length);

            return Convert.ToBase64String(result, 0, result.Length);
        }

        // <summary>
        /// 通过私钥解密，一般用作信息加密
        /// </summary>
        /// <param name="data">密文Base64</param>
        /// <param name="privateKey">私钥Base64</param>
        /// <returns>解密结果</returns>
        public static string DecryptByPrivateKey(string data, string privateKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(false, GetPrivateKey(privateKey));
            var bytes = Convert.FromBase64String(data);
            var result = engine.ProcessBlock(bytes, 0, bytes.Length);

            return Encoding.UTF8.GetString(result, 0, result.Length);
        }


        /// <summary>
        /// 通过私钥加密，一般用作信息签名
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="privateKey">Base64私钥</param>
        /// <returns>加密结果Base64</returns>
        public static string EncrpytByPrivateKey(string data, string privateKey) 
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(true, GetPrivateKey(privateKey));
            var bytes = Encoding.UTF8.GetBytes(data);
            var result = engine.ProcessBlock(bytes, 0, bytes.Length);

            return Convert.ToBase64String(result);
        }

        

        /// <summary>
        /// 通过公钥解密，一般用作信息验签
        /// </summary>
        /// <param name="data">Base64密文</param>
        /// <param name="publicKey">Base64公钥</param>
        /// <returns>解密结果</returns>
        public static string DecryptByPublicKey(string data, string publicKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(false, GetPublicKey(publicKey));
            var bytes = Convert.FromBase64String(data);
            var result = engine.ProcessBlock(bytes, 0, bytes.Length);

            return Encoding.UTF8.GetString(result, 0, result.Length);
        }

    }
}
