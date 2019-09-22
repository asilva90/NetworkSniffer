using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Data;

namespace NetworkSniffer.Model
{
    /// <summary>
    /// This class contains properties and methods used to split IP packet to header and message
    /// </summary>
    public class IPPacket
    {
        #region Fields
        private byte[] byteIPHeader;
        private byte[] byteIPMessage;
        private uint packetID;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes new instance of IPPacket class
        /// </summary>
        /// <param name="byteBuffer">Packet data to be parsed</param>
        /// <param name="length">Packet length</param>
        public IPPacket(byte[] byteBuffer, int length)
        {
            try
            {
                #region Buffer parsing
                MemoryStream memoryStream = new MemoryStream(byteBuffer, 0, length);
                
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                // First eight bytes are IP version and header length
                byte byteVersionAndHeaderLength = binaryReader.ReadByte();             

                // Shift 4 bits to the right to get version number
                byte version = (byte)(byteVersionAndHeaderLength >> 4);
                byte byteHeaderLength = 0;

                //protocolo IPv6 o cabeçalho é fixo 40 bytes
                if (version == 6)
                {
                    byteHeaderLength = 40;
                }
                else
                {
                    // First four bits are version and second four bits are header length
                    // Shift 4 bits to the left to remove first 4 bits
                    byteHeaderLength = (byte)(byteVersionAndHeaderLength << 4);
                    // Shift back to the right
                    byteHeaderLength >>= 4;
                    // Multiply by 4 to get actual length in bytes
                    byteHeaderLength *= 4;
                }

                // Copy header from byteBuffer to byteIPHeader
                byteIPHeader = new byte[byteHeaderLength];
                Array.Copy(byteBuffer, byteIPHeader, byteHeaderLength);

                // Copy message data from byteBuffer to byteIPMessage
                byteIPMessage = new byte[length - byteHeaderLength];
                Array.Copy(byteBuffer, byteHeaderLength, byteIPMessage, 0, length - byteHeaderLength);
                #endregion

                IPHeader = new List<IPHeader>();
                TCPPacket = new List<TCPPacket>();
                UDPPacket = new List<UDPPacket>();
                ICMPPacket = new List<ICMPPacket>();
                IGMPPacket = new List<IGMPPacket>();
                
                PopulatePacketContents(byteHeaderLength);

                ReceiveTime = DateTime.Now.ToString("HH:mm:ss");
            }
            catch (Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        #endregion

        #region Properties
        public byte[] ByteIPHeader
        {
            get
            {
                return byteIPHeader;
            }
        }

        public byte[] ByteIPMessage
        {
            get
            {
                return byteIPMessage;
            }
        }

        public uint PacketID
        {
            get
            {
                return packetID;
            }
            set
            {
                packetID = value;
            }
        }

        // Adding header to composite collection seems like best idea for displaying packet info
        // Both header and massage must be stored as a list so they could be put in CompositeCollection

        /// <summary>
        /// Holds only one element - header part of the IPPacket
        /// </summary>
        public List<IPHeader> IPHeader { get; set; }

        /// <summary>
        /// Holds IP message if transport protocol is TCP
        /// </summary>
        public List<TCPPacket> TCPPacket { get; set; }

        /// <summary>
        /// Holds IP message if transport protocol is UDP
        /// </summary>
        public List<UDPPacket> UDPPacket { get; set; }

        /// <summary>
        /// Holds IP message if transport protocol is ICMP
        /// </summary>
        public List<ICMPPacket> ICMPPacket { get; set; }

        /// <summary>
        /// Holds IP message if transport protocol is IGMP
        /// </summary>
        public List<IGMPPacket> IGMPPacket { get; set; }

        /// <summary>
        /// Composite collection that stores both header and message
        /// </summary>
        public IList PacketContent
        {
            get
            {
                return new CompositeCollection()
                {
                    new CollectionContainer() { Collection = IPHeader },
                    new CollectionContainer() { Collection = TCPPacket },
                    new CollectionContainer() { Collection = UDPPacket },
                    new CollectionContainer() { Collection = ICMPPacket },
                    new CollectionContainer() { Collection = IGMPPacket }
                };
            }
        }

        public string ReceiveTime { get; private set; }
        #endregion

        #region Methods
        /// <summary>
        /// This method fills PacketContents class with header information and data
        /// </summary>
        /// <param name="headerLength">Length of packet header used to parse it in the IPHeader constructor</param>
        private void PopulatePacketContents(byte headerLength)
        {
            IPHeader.Add(new IPHeader(byteIPHeader, headerLength));

            if (IPHeader[0].Version == 6)
            {
                bool possuiNextHeader = true;
                while(possuiNextHeader)
                {
                    switch (IPHeader[0].TransportProtocol)
                    {
                        case 0:
                            IPHeader[0].HopByHopHeader = new HopByHopHeader(ref byteIPMessage, byteIPMessage.Length);
                            IPHeader[0].TransportProtocol = IPHeader[0].HopByHopHeader.NextHeader;
                            break;
                        case 43:
                            IPHeader[0].RoutingHeader = new RoutingHeader(ref byteIPMessage, byteIPMessage.Length);
                            IPHeader[0].TransportProtocol = IPHeader[0].RoutingHeader.NextHeader;
                            break;
                        case 44:
                            IPHeader[0].FragmentationHeader = new FragmentationHeader(ref byteIPMessage, byteIPMessage.Length);
                            IPHeader[0].TransportProtocol = IPHeader[0].FragmentationHeader.NextHeader;
                            break;
                        case 50:
                            IPHeader[0].EncapsulationSecurityPayloadHeader = new EncapsulationSecurityPayloadHeader(ref byteIPMessage, byteIPMessage.Length);
                            IPHeader[0].TransportProtocol = IPHeader[0].EncapsulationSecurityPayloadHeader.NextHeader;
                            break;
                        case 51:
                            IPHeader[0].AuthenticationHeader = new AuthenticationHeader(ref byteIPMessage, byteIPMessage.Length);
                            IPHeader[0].TransportProtocol = IPHeader[0].AuthenticationHeader.NextHeader;
                            break;
                        case 60:
                            IPHeader[0].DestinationOptionsHeader = new DestinationOptionsHeader(ref byteIPMessage, byteIPMessage.Length);
                            IPHeader[0].TransportProtocol = IPHeader[0].DestinationOptionsHeader.NextHeader;
                            break;

                        default:
                            possuiNextHeader = false;
                            break;
                    }
                }
            }

            if (IPHeader[0].TransportProtocol == 1)
            {
                ICMPPacket.Add(new ICMPPacket(byteIPMessage, byteIPMessage.Length));
            }
            else if(IPHeader[0].TransportProtocol == 2)
            {
                IGMPPacket.Add(new IGMPPacket(byteIPMessage, byteIPMessage.Length));
            }
            else if(IPHeader[0].TransportProtocol == 6)
            {
                TCPPacket.Add(new TCPPacket(byteIPMessage, byteIPMessage.Length));
            }
            else if (IPHeader[0].TransportProtocol == 17)
            {
                UDPPacket.Add(new UDPPacket(byteIPMessage, byteIPMessage.Length));
            }
            else if (IPHeader[0].TransportProtocol == 58)
            {
                ICMPPacket.Add(new ICMPPacket(byteIPMessage, byteIPMessage.Length));
            }
        }
        #endregion
    }
}
