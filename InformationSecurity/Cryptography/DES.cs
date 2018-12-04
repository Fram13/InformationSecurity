using System;
using System.IO;

namespace InformationSecurity.Cryptography
{
    public class DES : EncryptionAlgorithm
    {
        private long[] masks;
        private int[] initialPermutationIndicies;
        private long[] keys;
        private int[,] substitutionMatrices;

        public DES()
        {
            masks = new long[64];
            masks[0] = 1;

            for (int i = 0; i < masks.Length - 1; i++)
            {
                masks[i + 1] = masks[i] << 1;
            }

            initialPermutationIndicies = new int[64];
            keys = new long[16];
            substitutionMatrices = new int[8, 64];
        }
        
        #region Encryption methods
        
        internal override void EncryptBlock(Block block)
        {
            block.Value = InitialPermutation(block.Value);

            for (int i = 0; i < 16; i++)
            {
                Round(block, keys[i]);
            }
            
            block.Swap();
            block.Value = InverseInitialPermutation(block.Value);
        }

        internal override void DecryptBlock(Block block)
        {
            block.Value = InitialPermutation(block.Value);

            for (int i = 0; i < 16; i++)
            {
                Round(block, keys[15 - i]);
            }

            block.Swap();
            block.Value = InverseInitialPermutation(block.Value);
        }
        
        private long InitialPermutation(long value)
        {
            long result = 0;
            
            for (int i = 0; i < initialPermutationIndicies.Length; i++)
            {
                long mask = masks[initialPermutationIndicies[i]];

                if ((value & mask) != 0)
                {
                    result |= masks[i];
                }
            }

            return result;
        }
        
        private long InverseInitialPermutation(long value)
        {
            long result = 0;
            
            for (int i = 0; i < initialPermutationIndicies.Length; i++)
            {
                long mask = masks[i];

                if ((value & mask) != 0)
                {
                    result |= masks[initialPermutationIndicies[i]];
                }
            }

            return result;
        }

        private void Round(Block block, long key)
        {
            int right = block.Right;
            block.Right = Substitution(ExpandingPermutation(right) ^ key) ^ block.Left;
            block.Left = right;
            
        }

        private long ExpandingPermutation(int value)
        {
            int[] tetrads = new int[8];

            for (int i = 0; i < tetrads.Length; i++)
            {
                tetrads[i] = value & 0x0000000F;
                value >>= 4;
            }

            long result = 0;

            for (int i = tetrads.Length - 1; i > -1; i--)
            {
                result <<= 6;
                
                int prev = i == 0 ? tetrads.Length - 1 : i - 1;
                int next = (i + 1) % tetrads.Length;

                if ((tetrads[prev] & 8) != 0)
                {
                    result |= 1;
                }

                result |= tetrads[i] << 1;
                
                if ((tetrads[next] & 1) != 0)
                {
                    result |= 32;
                }
            }

            return result;
        }
        
        private int Substitution(long value)
        {
            int result = 0;

            for (int i = 0; i < 8; i++)
            {
                result |= substitutionMatrices[i, value & 0x0000003F];
                value >>= 6;
            }

            return result;
        }
        
        #endregion Encryption methods
        
        #region Initialization methods
        
        public override void Initialize()
        {
            initialPermutationIndicies = Permutations.RandomPermutationOfIntegerNumber(64);
            
            int[] selectivePermutationIndicies = GenerateIndiciesForSelectivePermutation48From56();
            int[] shiftsInRound = {1, 2, 2, 1, 2, 1, 1, 2, 2, 2, 1, 1, 2, 2, 1, 1};
            long keyLeftMask = 0x000000000FFFFFFF;
            long keyRightMask = 0x00FFFFFFF0000000;
            Random randomizer = new Random();
            
            //Генерация ключей
            long key = SelectivePermutation56Form64(((long)randomizer.Next() << 32) | (randomizer.Next() & 0x00000000FFFFFFFF));

            for (int i = 0; i < 16; i++)
            {
                long leftKey = (key & keyLeftMask) << shiftsInRound[i];
                long rightKey = (key & keyRightMask) << shiftsInRound[i];

                if (shiftsInRound[i] == 1)
                {
                    leftKey |= (leftKey & masks[28]) != 0 ? 1 : 0;
                    rightKey |= (rightKey & masks[56]) != 0 ? masks[28] : 0;
                }
                else
                {
                    leftKey |= (leftKey & masks[28]) != 0 ? 1 : 0;
                    leftKey |= (leftKey & masks[29]) != 0 ? 2 : 0;
                    
                    rightKey |= (rightKey & masks[56]) != 0 ? masks[28] : 0;
                    rightKey |= (rightKey & masks[57]) != 0 ? masks[29] : 0;
                }

                key = leftKey | rightKey;
                keys[i] = SelectivePermutation48Form56(key, selectivePermutationIndicies);
            }
            
            //Инициализация матриц подстановки
            for (int i = 0; i < 8; i++)
            {
                int[] row1 = Permutations.RandomPermutationOfIntegerNumber(16);
                int[] row2 = Permutations.RandomPermutationOfIntegerNumber(16);
                int[] row3 = Permutations.RandomPermutationOfIntegerNumber(16);
                int[] row4 = Permutations.RandomPermutationOfIntegerNumber(16);

                for (int j = 0; j < 16; j++)
                {
                    substitutionMatrices[i, 2 * j] = row1[j] << (i * 4);
                    substitutionMatrices[i, 2 * j + 1] = row2[j] << (i * 4);
                    
                    substitutionMatrices[i, 2 * j + 32] = row3[j] << (i * 4);
                    substitutionMatrices[i, 2 * j + 33] = row4[j] << (i * 4);
                }
            }
        }

        private long SelectivePermutation56Form64(long value)
        {
            int[] basePermutation = Permutations.RandomPermutationOfIntegerNumber(64);
            int[] indicies = Permutations.RandomPermutationOfIntegerNumber(56);

            long result = 0;
            
            for (int i = 0; i < indicies.Length; i++)
            {
                long mask = masks[basePermutation[indicies[i]]];

                if ((value & mask) != 0)
                {
                    result |= masks[i];
                }
            }

            return result;
        }

        private int[] GenerateIndiciesForSelectivePermutation48From56()
        {
            int[] basePermutation = Permutations.RandomPermutationOfIntegerNumber(56);
            int[] indicies = Permutations.RandomPermutationOfIntegerNumber(48);
            int[] permutationIndicies = new int[48];

            for (int i = 0; i < indicies.Length; i++)
            {
                permutationIndicies[i] = basePermutation[indicies[i]];
            }

            return permutationIndicies;
        }
        
        private long SelectivePermutation48Form56(long value, int[] indicies)
        {
            long result = 0;
            
            for (int i = 0; i < indicies.Length; i++)
            {
                long mask = masks[indicies[i]];

                if ((value & mask) != 0)
                {
                    result |= masks[i];
                }
            }

            return result;
        }
        
        #endregion Initialization methods
        
        #region Serialization methods
        
        public override void SerializeToFile(string path)
        {
            using (Stream stream = new FileStream(path, FileMode.Create))
            using (BinaryWriter writer = new BinaryWriter(stream))
            {
                for (int i = 0; i < initialPermutationIndicies.Length; i++)
                {
                    writer.Write((byte)initialPermutationIndicies[i]);
                }
                
                for (int i = 0; i < keys.Length; i++)
                {
                    writer.Write(keys[i]);
                }
                
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 64; j++)
                    {
                        writer.Write(substitutionMatrices[i, j]);
                    }
                }
            }
        }

        public static DES DeserializeFromFile(string path)
        {
            DES encryptor = new DES();

            using (Stream stream = new FileStream(path, FileMode.Open))
            using (BinaryReader reader = new BinaryReader(stream))
            {
                for (int i = 0; i < encryptor.initialPermutationIndicies.Length; i++)
                {
                    encryptor.initialPermutationIndicies[i] = reader.ReadByte();
                }
                
                for (int i = 0; i < encryptor.keys.Length; i++)
                {
                    encryptor.keys[i] = reader.ReadInt64();
                }
                
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 64; j++)
                    {
                        encryptor.substitutionMatrices[i, j] = reader.ReadInt32();
                    }
                }
            }

            return encryptor;
        }
        
        #endregion Serialization methods
    }
}