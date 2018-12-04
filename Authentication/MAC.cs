using System;
using System.IO;
using InformationSecurity.Cryptography;

namespace InformationSecurity.Authentication
{
    public static class MAC
    {
        public static long Calculate(EncryptionAlgorithm encryptionAlgorithm, string sourcePath, string targetPath)
        {
            byte[] buffer = new byte[Block.Size];
            long prev = 0;
            Block block = new Block();

            using (Stream inputStream = new FileStream(sourcePath, FileMode.Open))
            using (Stream outputStream = new FileStream(targetPath, FileMode.Create))
            {
                int read = 0;

                while ((read = inputStream.Read(buffer, 0, Block.Size)) > 0)
                {
                    outputStream.Write(buffer, 0, read);

                    block.SetBytes(buffer);
                    block.Value ^= prev;
                    encryptionAlgorithm.EncryptBlock(block);
                    prev = block.Value;
                    buffer.Free();
                }

                outputStream.Write(block.GetBytes(), 0, Block.Size);
            }

            return block.Value;
        }

        public static Tuple<long, long> Validate(EncryptionAlgorithm algorithm, string sourcePath, string targetPath)
        {
            byte[] buffer = new byte[Block.Size];
            long prev = 0;
            Block block = new Block();

            using (Stream inputStream = new FileStream(sourcePath, FileMode.Open))
            using (Stream outputStream = new FileStream(targetPath, FileMode.Create))
            {
                long maxRead = inputStream.Length - 8;

                while (maxRead > 0)
                {
                    int read = inputStream.Read(buffer, 0, (int)Math.Min(Block.Size, maxRead));
                    outputStream.Write(buffer, 0, read);

                    maxRead -= read;                    
                    block.SetBytes(buffer);
                    block.Value ^= prev;
                    algorithm.EncryptBlock(block);
                    prev = block.Value;
                    buffer.Free();
                }

                using (BinaryReader reader = new BinaryReader(inputStream))
                {
                    return Tuple.Create(block.Value, reader.ReadInt64());
                }
            }
        }
    }
}
