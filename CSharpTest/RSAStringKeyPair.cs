using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CSharpTest
{
    public class RSAStringKeyPair
    {
        public string PrivateKey { private set; get; } 
        public string PublicKey { private set; get; }

        public RSAStringKeyPair(string privateKey, string publicKey) 
        {
            this.PrivateKey = privateKey;
            this.PublicKey = publicKey;
        }
    }
}
