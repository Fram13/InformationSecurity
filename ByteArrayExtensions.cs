namespace InformationSecurity
{
    internal static class ByteArrayExtensions
    {
        public static void Free(this byte[] buffer)
        {
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = 0;
            }
        }
    }
}
