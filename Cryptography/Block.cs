namespace InformationSecurity.Cryptography
{
    internal class Block
    {
        public const int Size = 8;

        public int Left { get; set; }
        public int Right { get; set; }

        public long Value
        {
            get => ((long)Right << 32) | (Left & 0x00000000FFFFFFFF);
            set
            {
                Left = (int)value;
                Right = (int)(value >> 32);
            }
        }

        public int Word1
        {
            get => Left & 0x0000FFFF;
            set
            {
                Left &= 0x0000FFFF << 16;
                Left |= value & 0x0000FFFF;
            }
        }

        public int Word2
        {
            get => (Left >> 16) & 0x0000FFFF;
            set
            {
                Left &= 0x0000FFFF;
                Left |= (value & 0x0000FFFF) << 16;
            }
        }

        public int Word3
        {
            get => Right & 0x0000FFFF;
            set
            {
                Right &= 0x0000FFFF << 16;
                Right |= value & 0x0000FFFF;
            }
        }

        public int Word4
        {
            get => (Right >> 16) & 0x0000FFFF;
            set
            {
                Right &= 0x0000FFFF;
                Right |= (value & 0x0000FFFF) << 16;
            }
        }

        public void Swap()
        {
            int temp = Left;
            Left = Right;
            Right = temp;
        }

        public byte[] GetBytes()
        {
            byte[] bytes = new byte[Size];

            int left = Left;
            int right = Right;

            for (int i = 0; i < 4; i++)
            {
                bytes[i] = (byte)(left & 0x000000FF);
                left >>= 8;

                bytes[i + 4] = (byte)(right & 0x000000FF);
                right >>= 8;
            }

            return bytes;
        }

        public void SetBytes(byte[] bytes)
        {
            Left = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
            Right = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
        }
    }
}
