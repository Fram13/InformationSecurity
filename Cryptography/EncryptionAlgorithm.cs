using System.IO;

namespace InformationSecurity.Cryptography
{
    public abstract class EncryptionAlgorithm
    {
        internal abstract void EncryptBlock(Block block);
        internal abstract void DecryptBlock(Block block);
        public abstract void Initialize();
        public abstract void SerializeToFile(string path);
    }
}
