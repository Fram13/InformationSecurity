using System;
using System.IO;

namespace InformationSecurity.Cryptography
{
    public class GOST28147 : EncryptionAlgorithm
    {
        private const int KeyCount = 8;
        private const int SubstitutionMatrixRows = 16;
        private const int SubstitutionMatrixColumns = 8;

        int[] keys;
        int[,] substitutionMatrix;
        int[] masks;

        public GOST28147()
        {
            keys = new int[KeyCount];
            substitutionMatrix = new int[SubstitutionMatrixRows, SubstitutionMatrixColumns];
            masks = new int[SubstitutionMatrixColumns];
            
            int mask = 0x0000000F;

            for (int i = 0; i < SubstitutionMatrixColumns; i++)
            {
                masks[i] = mask;
                mask <<= 4;
            }
        }
        
        public override void Initialize()
        {
            Random random = new Random();

            for (int i = 0; i < KeyCount; i++)
            {
                keys[i] = random.Next();
            }

            for (int i = 0; i < SubstitutionMatrixColumns; i++)
            {
                int[] values = Permutations.RandomPermutationOfIntegerNumber(SubstitutionMatrixRows);

                for (int j = 0; j < SubstitutionMatrixRows; j++)
                {
                    substitutionMatrix[j, i] = values[j] << (i * 4);
                }
            }
        }

        private void Round(Block block, int currentRound)
        {
            block.Left ^= Substitution(block.Right, keys[currentRound]);
            block.Swap();
        }

        private int Substitution(int value, int key)
        {
            int m32 = value + key;

            for (int i = 0; i < SubstitutionMatrixColumns; i++)
            {
                int rowIndex = m32 & masks[i];
                m32 ^= rowIndex;
                rowIndex >>= i * 4;
                rowIndex &= 0x0000000F;
                m32 |= substitutionMatrix[rowIndex, i];
            }

            long buffer = m32;
            buffer &= 0x00000000FFFFFFFF;
            buffer <<= 11;

            int left = (int)buffer;
            buffer >>= 32;
            int right = (int)buffer;
            
            m32 = left | right;

            return m32;
        }

        internal override void EncryptBlock(Block block)
        {
            for (int i = 0; i < KeyCount * 3; i++)
            {
                Round(block, i % KeyCount);
            }

            for (int i = KeyCount - 1; i >= 0; i--)
            {
                Round(block, i);
            }

            block.Swap();
        }

        internal override void DecryptBlock(Block block)
        {
            for (int i = 0; i < KeyCount; i++)
            {
                Round(block, i);
            }

            for (int i = KeyCount * 3 - 1; i >= 0; i--)
            {
                Round(block, i % KeyCount);
            }

            block.Swap();
        }

        public static GOST28147 DeserializeFromFile(string path)
        {
            GOST28147 encryptor = new GOST28147();

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
    }
}
