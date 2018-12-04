using System;

namespace InformationSecurity.Cryptography
{
    internal static class Permutations
    {
        private static readonly Random Randomizer = new Random();
        
        public static int[] RandomPermutationOfIntegerNumber(int count)
        {
            int[] permutation = new int[count];
            int[] randomValues = new int[count];

            for (int i = 0; i < count; i++)
            {
                randomValues[i] = Randomizer.Next();
                permutation[i] = i;
            }

            for (int i = 0; i < count - 1; i++)
            {
                for (int j = 0; j < count - 1; j++)
                {
                    if (randomValues[j] > randomValues[j + 1])
                    {
                        int temp = randomValues[j];
                        randomValues[j] = randomValues[j + 1];
                        randomValues[j + 1] = temp;

                        temp = permutation[j];
                        permutation[j] = permutation[j + 1];
                        permutation[j + 1] = temp;
                    }
                }
            }

            return permutation;
        }
    }
}