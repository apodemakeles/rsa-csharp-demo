using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CSharpTest
{
    public class RSAPEMKeyPair
    {
        public string PrivateKey { private set; get; } 
        public string PublicKey { private set; get; }

        public RSAPEMKeyPair(string privateKey, string publicKey) 
        {
            this.PrivateKey = privateKey;
            this.PublicKey = publicKey;
        }
    }
}
