using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using System.Collections.Generic;

namespace CSharpTest
{
    public class RSAUtils
    {
        public static readonly IDictionary<string,string> HASH_ALGORITHM;

        static RSAUtils(){
            HASH_ALGORITHM = new Dictionary<string,string>();
            HASH_ALGORITHM.Add("MD5","MD5withRSA");
            HASH_ALGORITHM.Add("SHA1", "SHA1withRSA");
            HASH_ALGORITHM.Add("SHA256","SHA256withRSA");
        }


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

        public static RSAPEMKeyPair GenKeyPEM(int keysize)
        {
            RsaKeyPairGenerator r = new RsaKeyPairGenerator();
            r.Init(new KeyGenerationParameters(new SecureRandom(), keysize));
            AsymmetricCipherKeyPair keyPair = r.GenerateKeyPair();


            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);
            pemWriter.WriteObject(keyPair.Private);
            pemWriter.Writer.Flush();

            string privateKey = textWriter.ToString();
           
            TextWriter textpubWriter = new StringWriter();
            PemWriter pempubWriter = new PemWriter(textpubWriter);
            pempubWriter.WriteObject(keyPair.Public);
            pempubWriter.Writer.Flush();
            string publicKey = textpubWriter.ToString();

            return new RSAPEMKeyPair(privateKey, publicKey);
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
        public static byte[] Decrypt(byte[] data, byte[] privateKey)
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
        public static byte[] Encrypt(byte[] data, byte[] publicKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            engine.Init(true, GetPublicKey(publicKey));

            return engine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// 通过私钥签名
        /// </summary>
        /// <param name="data">明文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="hashAlgorithm">哈希算法</param>
        /// <returns></returns>
        public static byte[] sign(byte[] data, byte[] privateKey, string hashAlgorithm)
        {
            ISigner signer = SignerUtilities.GetSigner(HASH_ALGORITHM[hashAlgorithm].ToUpper());
            signer.Init(true, GetPrivateKey(privateKey));
            signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }


        public static bool verify(byte[] data, byte[] publicKey, byte[] sign, string hashAlgorithm)
        {
            ISigner signer = SignerUtilities.GetSigner(HASH_ALGORITHM[hashAlgorithm].ToUpper());
            signer.Init(false, GetPublicKey(publicKey));
            signer.BlockUpdate(data, 0, data.Length);

            return signer.VerifySignature(sign);

        }

    }
}
