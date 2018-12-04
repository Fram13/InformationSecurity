using System;
using System.IO;

namespace InformationSecurity.Cryptography
{
    public class Blowfish : EncryptionAlgorithm
    {
        private const int KeyCount = 18;
        private const int BaseKeyCount = 14;
        private const int SubstitutionMatrixRows = 4;
        private const int SubstitutionMatrixColumns = 256;
        private const int RoundCount = 16;

        private int[] keys;
        private int[,] substitutionMatrix;

        public Blowfish()
        {
            keys = new int[KeyCount];
            substitutionMatrix = new int[SubstitutionMatrixRows, SubstitutionMatrixColumns];
        }

        public override void Initialize()
        {
            Random random = new Random();

            //Шаг 1: инициализация массивов случайными значениями
            for (int i = 0; i < KeyCount; i++)
            {
                keys[i] = random.Next();
            }

            int[] baseKeys = new int[BaseKeyCount];

            for (int i = 0; i < BaseKeyCount; i++)
            {
                baseKeys[i] = random.Next();
            }

            for (int i = 0; i < SubstitutionMatrixRows; i++)
            {
                for (int j = 0; j < SubstitutionMatrixColumns; j++)
                {
                    substitutionMatrix[i, j] = random.Next();
                }
            }

            //Шаг 2: операция XOR над keys и baseKeys
            for (int i = 0, j = 0; i < KeyCount; i++, j++)
            {
                keys[i] ^= baseKeys[j % BaseKeyCount];
            }

            //Шаг 3: шифрование ключей и таблиц замен
            Block block = new Block();

            for (int i = 0; i < KeyCount; i += 2)
            {
                EncryptBlock(block);
                keys[i] = block.Left;
                keys[i + 1] = block.Right;
            }

            for (int i = 0; i < SubstitutionMatrixRows; i++)
            {
                for (int j = 0; j < SubstitutionMatrixColumns; j += 2)
                {
                    EncryptBlock(block);
                    substitutionMatrix[i, j] = block.Left;
                    substitutionMatrix[i, j + 1] = block.Right;
                }
            }
        }

        private void Round(Block block, int currentRound)
        {
            block.Left ^= keys[currentRound];
            block.Right ^= Substitution(block.Left);
            block.Swap();
        }

        private int Substitution(int value)
        {
            //Индексы для матриц подстановок подставляются последовательно, в порядке следования в памяти
            int[] indicies = new int[4];

            for (int i = 0; i < indicies.Length; i++)
            {
                indicies[i] = value & 0x000000FF;
                value >>= 8;
            }

            int result = substitutionMatrix[0, indicies[0]] ^ substitutionMatrix[1, indicies[1]];
            result += substitutionMatrix[2, indicies[2]];
            result ^= substitutionMatrix[3, indicies[3]];

            return result;
        }

        public override void SerializeToFile(string path)
        {
            using (Stream stream = new FileStream(path, FileMode.Create))
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                for (int i = 0; i < KeyCount; i++)
                {
                    writer.Write(keys[i]);
                }

                for (int i = 0; i < SubstitutionMatrixRows; i++)
                {
                    for (int j = 0; j < SubstitutionMatrixColumns; j++)
                    {
                        writer.Write(substitutionMatrix[i, j]);
                    }
                }
            }
        }
        
        public static Blowfish DeserializeFromFile(string path)
        {
            Blowfish encryptor = new Blowfish();
            
            using (Stream stream = new FileStream(path, FileMode.Open))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                for (int i = 0; i < KeyCount; i++)
                {
                    encryptor.keys[i] = reader.ReadInt32();
                }

                for (int i = 0; i < SubstitutionMatrixRows; i++)
                {
                    for (int j = 0; j < SubstitutionMatrixColumns; j++)
                    {
                        encryptor.substitutionMatrix[i, j] = reader.ReadInt32();
                    }
                }
            }

            return encryptor;
        }

        internal override void DecryptBlock(Block block)
        {
            for (int i = 0; i < RoundCount; i++)
            {
                Round(block, RoundCount + 1 - i);
            }

            block.Swap();
            block.Left ^= keys[0];
            block.Right ^= keys[1];
        }

        internal override void EncryptBlock(Block block)
        {
            for (int i = 0; i < RoundCount; i++)
            {
                Round(block, i);
            }

            block.Swap();
            block.Left ^= keys[17];
            block.Right ^= keys[16];
        }
    }
}
