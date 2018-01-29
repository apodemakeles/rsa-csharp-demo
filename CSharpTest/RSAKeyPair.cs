using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CSharpTest
{
    public class RSAKeyPair
    {
        public byte[] PrivateKey { private set; get; }
        public byte[] PublicKey { private set; get; }

        public RSAKeyPair(byte[] privateKey, byte[] publicKey)
        {
            this.PrivateKey = privateKey;
            this.PublicKey = publicKey;
        }
    }
}
