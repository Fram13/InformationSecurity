using System;
using System.IO;

namespace InformationSecurity.Cryptography
{
    public class IDEA : EncryptionAlgorithm
    {
        private int[] encryptionKeys;
        private int[] decryptionKeys;

        public IDEA()
        {
            encryptionKeys = new int[52];
            decryptionKeys = new int[52];
        }

        public override void Initialize()
        {
            Random random = new Random();

            long initialKeyLeft = ((long)random.Next() << 32) | (random.Next() & 0x00000000FFFFFFFFL);
            long initialKeyRight = ((long)random.Next() << 32) | (random.Next() & 0x00000000FFFFFFFFL);
            long left25bitsMask = 0x0000000001FFFFFFL;
            long right25bitsMask = left25bitsMask << 39;

            //генерация подключей шифрования
            for (int i = 0; i < 6; i++)
            {
                long tempLeft = initialKeyLeft;
                long tempRight = initialKeyRight;

                for (int j = 0; j < 4; j++)
                {
                    encryptionKeys[i * 8 + j] = (int)(tempLeft & 0x000000000000FFFFL);
                    encryptionKeys[i * 8 + j + 4] = (int)(tempRight & 0x000000000000FFFFL);
                    tempLeft >>= 16;
                    tempRight >>= 16;
                }
                
                long bitsOfLeftKey = ((initialKeyLeft & right25bitsMask) >> 39) & left25bitsMask;
                long bitsOfRightKey = ((initialKeyRight & right25bitsMask) >> 39) & left25bitsMask;
                initialKeyLeft = (initialKeyLeft << 25) | bitsOfRightKey;
                initialKeyRight = (initialKeyRight << 25) | bitsOfLeftKey;
            }
            
            for (int i = 0; i < 4; i++)
            {
                encryptionKeys[48 + i] = (int)(initialKeyLeft & 0x000000000000FFFFL);
                initialKeyLeft >>= 16;
            }

            GenerateDecryptionKeys();
        }

        public override void SerializeToFile(string path)
        {
            using (Stream stream = new FileStream(path, FileMode.Create))
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                for (int i = 0; i < encryptionKeys.Length; i++)
                {
                    writer.Write((short)encryptionKeys[i]);
                }
            }
        }

        public static IDEA DeserializeFromFile(string path)
        {
            IDEA encryptor = new IDEA();

            using (Stream stream = new FileStream(path, FileMode.Open))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                for (int i = 0; i < encryptor.encryptionKeys.Length; i++)
                {
                    encryptor.encryptionKeys[i] = reader.ReadUInt16();
                }
            }

            encryptor.GenerateDecryptionKeys();

            return encryptor;
        }

        internal override void DecryptBlock(Block block)
        {
            for (int i = 0; i < 8; i++)
            {
                Round(block,
                    decryptionKeys[6 * i],
                    decryptionKeys[6 * i + 1],
                    decryptionKeys[6 * i + 2],
                    decryptionKeys[6 * i + 3],
                    decryptionKeys[6 * i + 4],
                    decryptionKeys[6 * i + 5]);
            }

            int temp = block.Word2;
            block.Word2 = block.Word3;
            block.Word3 = temp;

            InitialTransformation(block, decryptionKeys[48], decryptionKeys[49], decryptionKeys[50], decryptionKeys[51]);
        }

        internal override void EncryptBlock(Block block)
        {
            for (int i = 0; i < 8; i++)
            {
                Round(block,
                    encryptionKeys[6 * i],
                    encryptionKeys[6 * i + 1],
                    encryptionKeys[6 * i + 2],
                    encryptionKeys[6 * i + 3],
                    encryptionKeys[6 * i + 4],
                    encryptionKeys[6 * i + 5]);
            }

            int temp = block.Word2;
            block.Word2 = block.Word3;
            block.Word3 = temp;

            InitialTransformation(block, encryptionKeys[48], encryptionKeys[49], encryptionKeys[50], encryptionKeys[51]);
        }

        private void GenerateDecryptionKeys()
        {
            for (int i = 0; i < 8; i++)
            {
                int j = 46 - i * 6;

                decryptionKeys[i * 6] = InverseValueByModulo(encryptionKeys[j + 2]);

                if (i == 0)
                {
                    decryptionKeys[i * 6 + 1] = -encryptionKeys[j + 3] & 0x0000FFFF;
                    decryptionKeys[i * 6 + 2] = -encryptionKeys[j + 4] & 0x0000FFFF;
                }
                else
                {
                    decryptionKeys[i * 6 + 1] = -encryptionKeys[j + 4] & 0x0000FFFF;
                    decryptionKeys[i * 6 + 2] = -encryptionKeys[j + 3] & 0x0000FFFF;
                }

                decryptionKeys[i * 6 + 3] = InverseValueByModulo(encryptionKeys[j + 5]);
                decryptionKeys[i * 6 + 4] = encryptionKeys[j];
                decryptionKeys[i * 6 + 5] = encryptionKeys[j + 1];
            }

            decryptionKeys[48] = InverseValueByModulo(encryptionKeys[0]);
            decryptionKeys[49] = -encryptionKeys[1] & 0x0000FFFF;
            decryptionKeys[50] = -encryptionKeys[2] & 0x0000FFFF;
            decryptionKeys[51] = InverseValueByModulo(encryptionKeys[3]);
        }

        private int InverseValueByModulo(int value)
        {
            int result = 0;

            for (int i = 1; i < 65536; i++)
            {
                if (1L * i * value % 65537 == 1)
                {
                    result = i;
                    break;
                }
            }

            return result;
        }

        private void Round(Block block, int k1, int k2, int k3, int k4, int k5, int k6)
        {
            InitialTransformation(block, k1, k2, k3, k4);

            int res1 = MultiplyByModulo(block.Word1 ^ block.Word3, k5);
            int res2 = AddByModulo(res1, block.Word2 ^ block.Word4);
            int res3 = MultiplyByModulo(res2, k6);
            int res4 = AddByModulo(res1, res3);

            block.Word1 = block.Word1 ^ res3;
            block.Word2 = block.Word2 ^ res4;
            block.Word3 = block.Word3 ^ res3;
            block.Word4 = block.Word4 ^ res4;

            int temp = block.Word2;
            block.Word2 = block.Word3;
            block.Word3 = temp;
        }

        private void InitialTransformation(Block block, int k1, int k2, int k3, int k4)
        {
            block.Word1 = MultiplyByModulo(block.Word1, k1);
            block.Word2 = AddByModulo(block.Word2, k2);
            block.Word3 = AddByModulo(block.Word3, k3);
            block.Word4 = MultiplyByModulo(block.Word4, k4);
        }

        private int AddByModulo(int left, int right)
        {
            return (left + right) % 65536;
        }

        private int MultiplyByModulo(int left, int right)
        {
            if (left == 0)
            {
                left = 65536;
            }

            if (right == 0)
            {
                right = 65536;
            }

            return (int)((1L * left * right) % 65537);
        }
    }
}