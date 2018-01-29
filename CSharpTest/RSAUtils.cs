using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace CSharpTest
{
    public class RSAUtils
    {
        /// <summary>
        /// 产生密钥对
        /// </summary>
        /// <param name="keysize">密钥长度，一般为256, 1024, 2048</param>
        /// <returns></returns>
        public static RSAKeyPair GenKeyPair(int keysize)
        {
            RsaKeyPairGenerator r = new RsaKeyPairGenerator();
            r.Init(new KeyGenerationParameters(new SecureRandom(), keysize));
            AsymmetricCipherKeyPair keyPair = r.GenerateKeyPair();

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetEncoded();
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetEncoded();

            return new RSAKeyPair(privateKeyInfo, publicKeyInfo);
        }

        private static AsymmetricKeyParameter GetPublicKey(byte[] s)
        {
            return PublicKeyFactory.CreateKey(s);
        }

        private static AsymmetricKeyParameter GetPrivateKey(byte[] s)
        {
            return PrivateKeyFactory.CreateKey(s);
        }

        /// <summary>
        /// 通过私钥解密，一般用作信息加密
        /// </summary>
        /// <param name="data">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>解密结果</returns>
        public static byte[] DecryptByPrivateKey(byte[] data, byte[] privateKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(false, GetPrivateKey(privateKey));

            return engine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// 通过公钥加密，一般用作信息解密
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>加密结果</returns>
        public static byte[] EncrpytByPublicKey(byte[] data, byte[] publicKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(true, GetPublicKey(publicKey));

            return engine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// 通过私钥加密，一般用作信息签名
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>加密结果</returns>
        public static byte[] EncrpytByPrivateKey(byte[] data, byte[] privateKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(true, GetPrivateKey(privateKey));

            return engine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// 通过公钥解密，一般用作信息验签
        /// </summary>
        /// <param name="data">密文</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>解密结果</returns>
        public static byte[] DecryptByPublicKey(byte[] data, byte[] publicKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(false, GetPublicKey(publicKey));

            return engine.ProcessBlock(data, 0, data.Length);
        }

    }
}
