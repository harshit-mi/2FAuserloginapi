namespace Ecos.Common.Utils;

public static class Generator
{
    public static string VerifyCode()
    {
        string number = new Random().Next(0, 999999).ToString("D6");
        if (number.Length < 6)
        {
            VerifyCode();
        }

        return number;
    }
}