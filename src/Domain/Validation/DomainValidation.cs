﻿using System.Text;

namespace Ecos.Domain.Validation
{
    public class DomainValidation
    {
        public DomainValidation() { }
        public static bool IsNumeric(string value)
        {
            return value.All(char.IsNumber);
        }
        public static string CreatePassword(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            while (0 < length--)
            {
                res.Append(valid[rnd.Next(valid.Length)]);
            }
            return res.ToString();
        }
    }
}
