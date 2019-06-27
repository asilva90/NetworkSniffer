using System;
using System.IO;
using System.Net;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class is used to parse and store IGMP header fields
    /// </summary>
    public class FragmentationHeader
    {
        #region Constructors
        /// <summary>
        /// Initializes new instance of IGMPHeader class
        /// </summary>
        /// <param name="byteBuffer">Byte array containing header data</param>
        /// <param name="length">Size of header in bytes</param>
        public FragmentationHeader(ref byte[] byteBuffer, int length)
        {
            MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);

            BinaryReader binaryReader = new BinaryReader(memoryStream);

            NextHeader = binaryReader.ReadByte();

            Length = binaryReader.ReadByte();

            TotalLength = (ushort)(Length + 8); // * do NextHeader

            //Remove os bytes do cabeçalho do início da mensagem
            byte[] byteBufferAux = new byte[length - TotalLength];
            Array.Copy(byteBuffer, TotalLength, byteBufferAux, 0, length - TotalLength);
            byteBuffer = byteBufferAux;
        }
        #endregion

        #region Properties
        public byte NextHeader { get; set; }

        public string NextHeaderFormat
        {
            get
            {
                switch (NextHeader)
                {
                    case 0:
                        return "Hop-by-Hop (" + NextHeader + ")";
                    case 1:
                        return "ICMP (" + NextHeader + ")";
                    case 2:
                        return "IGMP (" + NextHeader + ")";
                    case 6:
                        return "TCP (" + NextHeader + ")";
                    case 17:
                        return "UDP (" + NextHeader + ")";
                    case 43:
                        return "Routing (" + NextHeader + ")";
                    case 44:
                        return "Fragmentation (" + NextHeader + ")";
                    case 50:
                        return "Encapsulation Security Payload (" + NextHeader + ")";
                    case 51:
                        return "Authentication (" + NextHeader + ")";
                    case 58:
                        return "ICMPv6 (" + NextHeader + ")";
                    case 60:
                        return "Destination Options (" + NextHeader + ")";
                    default:
                        return "Unknown";
                }
            }
        }

        public byte Length { get; set; }

        public ushort TotalLength { get; set; }
        #endregion
    }
}
