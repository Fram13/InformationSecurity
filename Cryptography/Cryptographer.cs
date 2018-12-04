using System.IO;

namespace InformationSecurity.Cryptography
{
    public static class Cryptographer
    {
        public static void EncryptFile(EncryptionAlgorithm algorithm, string sourcePath, string targetPath)
        {
            byte[] buffer = new byte[Block.Size];
            int read;
            Block block = new Block();

            using (Stream inputStream = new FileStream(sourcePath, FileMode.Open))
            using (Stream outputStream = new FileStream(targetPath, FileMode.Create))
            {
                while ((read = inputStream.Read(buffer, 0, Block.Size)) == Block.Size)
                {
                    block.SetBytes(buffer);
                    algorithm.EncryptBlock(block);
                    outputStream.Write(block.GetBytes(), 0, Block.Size);
                    buffer.Free();
                }

                if (read > 0)
                {
                    block.SetBytes(buffer);
                    algorithm.EncryptBlock(block);
                    outputStream.Write(block.GetBytes(), 0, Block.Size);

                    //записывается количество прочитанных байт
                    buffer[0] = (byte)(read & 0x000000FF);
                    outputStream.Write(buffer, 0, 1);
                }
            }
        }

        public static void DecryptFile(EncryptionAlgorithm algorithm, string sourcePath, string targetPath)
        {
            byte[] currentBlock = new byte[Block.Size];
            byte[] nextBlock = new byte[Block.Size];
            int read;
            Block block = new Block();

            using (Stream inputStream = new FileStream(sourcePath, FileMode.Open))
            using (Stream outputStream = new FileStream(targetPath, FileMode.Create))
            {
                inputStream.Read(currentBlock, 0, Block.Size);

                do
                {
                    block.SetBytes(currentBlock);
                    algorithm.DecryptBlock(block);
                    read = inputStream.Read(nextBlock, 0, Block.Size);

                    if (read == 1)
                    {
                        //записывается количество значящих байт
                        outputStream.Write(block.GetBytes(), 0, nextBlock[0]);
                    }
                    else
                    {
                        outputStream.Write(block.GetBytes(), 0, Block.Size);

                        byte[] temp = currentBlock;
                        currentBlock = nextBlock;
                        nextBlock = temp;
                        nextBlock.Free();
                    }
                } while (read == Block.Size);
            }
        }
    }
}
