using System;
using InformationSecurity.Cryptography;
using InformationSecurity.Authentication;
using System.Linq;

namespace InformationSecurity
{
    internal class Program
    {
        private static bool ValidateFilePath(string path)
        {
            string lower = path.ToLower().Split('\\').Last();

            if (lower.Last() == ' ' || lower.Last() == '.')
            {
                return false;
            }

            if (lower.Contains("<") || lower.Contains(">") || lower.Contains(":") || lower.Contains("\"") ||
                lower.Contains("\\") || lower.Contains("/") || lower.Contains("|") || lower.Contains("?") ||
                lower.Contains("*") || lower.Equals("con") || lower.Equals("prn") || lower.Equals("aux") ||
                lower.Equals("nul") || lower.Equals("com1") || lower.Equals("com2") || lower.Equals("com3") ||
                lower.Equals("com4") || lower.Equals("com5") || lower.Equals("com6") || lower.Equals("com7") ||
                lower.Equals("com8") || lower.Equals("com9") || lower.Equals("lpt1") || lower.Equals("lpt2") ||
                lower.Equals("lpt3") || lower.Equals("lpt4") || lower.Equals("lpt5") || lower.Equals("lpt6") ||
                lower.Equals("lpt7") || lower.Equals("lpt8") || lower.Equals("lpt9"))
            {
                return false;
            }

            return true;
        }

        private static string GetPathFormConsole(string message)
        {
            Console.WriteLine(message);
            string path = Console.ReadLine();

            while (!ValidateFilePath(path))
            {
                Console.WriteLine("Неправльное имя файла.");
                Console.WriteLine(message);
                path = Console.ReadLine();
            }

            return path;
        }

        private static void Main(string[] args)
        {
            Console.WriteLine("Запись MAC-кода в конец файла");
            string path = GetPathFormConsole("Введите имя файла для хранения ключевой информации генератора MAC-кода:");
            string sourcePath = GetPathFormConsole("Введите имя исходного файла:");
            string targetPath = GetPathFormConsole("Введите имя целевого файла:");

            DES enc = new DES();
            enc.Initialize();
            enc.SerializeToFile(path);

            long mac = MAC.Calculate(enc, sourcePath, targetPath);
            Console.WriteLine("MAC-код файла: 0x{0:x16}", mac);
            Console.WriteLine("Для продолжения нажмите любую клавишу. . .");
            Console.ReadKey();
        }
    }
}