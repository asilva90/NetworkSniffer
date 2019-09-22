using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetworkSniffer.Model
{
    public static class Util
    {
        public static byte[] HexToDec(string[] valuesHex)
        {
            byte[] result = new byte[valuesHex.Length];
            int i = 0;
            foreach (var hexNumber in valuesHex)
            {
                result[i++] = (byte)Convert.ToInt32(hexNumber, 16);
            }

            return result;
        }
    }
}
