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
        

        /// <summary>
        /// 通过公钥加密，一般用作信息解密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="publicKey">公钥Base64</param>
        /// <returns>加密结果Base64</returns>
        public static string Encrypt(string data, string publicKey)      
        {
            var result = RSAUtils.Encrypt(Encoding.UTF8.GetBytes(data), Convert.FromBase64String(publicKey));                               

            return Convert.ToBase64String(result, 0, result.Length);
        }

        // <summary>
        /// 通过私钥解密，一般用作信息加密
        /// </summary>
        /// <param name="data">密文Base64</param>
        /// <param name="privateKey">私钥Base64</param>
        /// <returns>解密结果</returns>
        public static string Decrypt(string data, string privateKey)
        {
            var result = RSAUtils.Decrypt(Convert.FromBase64String(data), Convert.FromBase64String(privateKey));

            return Encoding.UTF8.GetString(result, 0, result.Length);
        }

        /// <summary>
        /// 通过私钥签名
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="privateKey">私钥Base64</param>
        /// <param name="hashAlgorithm">哈希算法</param>
        /// <returns>签名结果Base64</returns>
        public static string SignToBase64(string data, string privateKey, string hashAlgorithm)
        {
            var result = RSAUtils.sign(
                Encoding.UTF8.GetBytes(data), 
                Convert.FromBase64String(privateKey), 
                hashAlgorithm);

            return Convert.ToBase64String(result);
        }

        /// <summary>
        /// 通过公钥验签
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="publicKey">公钥Base64</param>
        /// <param name="sign">签名Base64</param>
        /// <param name="hashAlgorithm">哈希算法</param>
        /// <returns></returns>
        public static bool VerifyFromBase64(string data, string publicKey, string sign, string hashAlgorithm)
        {
            return RSAUtils.verify(
                Encoding.UTF8.GetBytes(data), 
                Convert.FromBase64String(publicKey), 
                Convert.FromBase64String(sign), 
                hashAlgorithm);
        }

    }
}
