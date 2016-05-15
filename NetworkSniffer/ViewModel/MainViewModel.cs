using GalaSoft.MvvmLight;
using GalaSoft.MvvmLight.Command;
using System.Windows.Input;
using System.Collections.ObjectModel;
using System.Net;
using NetworkSniffer.Model;
using System.Net.Sockets;
using System;
using System.Windows;
using System.Windows.Data;
using System.Text;
using System.Windows.Documents;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Microsoft.VisualBasic;

namespace NetworkSniffer.ViewModel
{
    /// <summary>
    /// This class contains properties that the main View can data bind to.
    /// </summary>
    public class MainViewModel : ViewModelBase
    {
        #region Members
        private SnifferViewModel snifferViewModel = new SnifferViewModel();
        private AnalyzerViewModel analyzerViewModel = new AnalyzerViewModel();
        private HelpViewModel helpViewModel = new HelpViewModel();

        private InterfaceMonitor monitor;
        private string filter;
        private readonly object packetListLock = new object();
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the MainViewModel class.
        /// </summary>
        public MainViewModel()
        {
            filter = "";
            CurrentViewModel = snifferViewModel;
            OpenAnalyzer = new RelayCommand(() => OpenAnalyzerExecute());
            OpenSniffer = new RelayCommand(() => OpenSnifferExecute());
            OpenHelp = new RelayCommand(() => OpenHelpExecute());
            StartCapture = new RelayCommand(() => StartCaptureExecute());
            StopCapture = new RelayCommand(() => StopCaputureExecute());
            ClearPacketList = new RelayCommand(() => ClearPacketListExecute());
            ResetFilter = new RelayCommand(() => ResetFilterExecute());
            ApplyFilter = new RelayCommand(() => ApplyFilterExecute());

            DeviceAddressList = new ObservableCollection<string>();
            PacketList = new ObservableCollection<IPPacket>();
            FilteredPacketList = new ObservableCollection<IPPacket>();
            SelectedPacketTree = new ObservableCollection<IPPacket>();
            GetAddresses();
        }
        #endregion

        #region Properties
        private ViewModelBase currentViewModel;
        public ViewModelBase CurrentViewModel
        {
            get
            {
                return currentViewModel;
            }
            set
            {
                currentViewModel = value;
                RaisePropertyChanged("CurrentViewModel");
            }
        }

        // List for storing all captured packets
        private ObservableCollection<IPPacket> packetList;
        public ObservableCollection<IPPacket> PacketList
        {
            get
            {
                return packetList;
            }
            set
            {
                packetList = value;
                // Enables access to packetList from different threads
                BindingOperations.EnableCollectionSynchronization(packetList, packetListLock);
            }
        }

        // List of filtered packets from PacketList that will be displayed on ViewList
        private ObservableCollection<IPPacket> filteredPacketList;
        public ObservableCollection<IPPacket> FilteredPacketList
        {
            get
            {
                return filteredPacketList;
            }
            set
            {
                filteredPacketList = value;
                // Enables access to packetList from different threads
                BindingOperations.EnableCollectionSynchronization(filteredPacketList, packetListLock);
            }
        }

        // packet selected in listview
        private IPPacket selectedPacket;
        public IPPacket SelectedPacket
        {
            get
            {
                return selectedPacket;
            }
            set
            {
                selectedPacket = value;
                // There can be only one selected packet, so the list must be empty
                SelectedPacketTree.Clear();
                SelectedPacketTree.Add(selectedPacket);
                RaisePropertyChanged("SelectedPacket");
                RaisePropertyChanged("HexPacketData");
                RaisePropertyChanged("CharPacketData");
            }
        }

        // Since TreeView ItemsSource must be bound to the ObservableCollection, 
        // selected packet must be ObservableCollection 
        public ObservableCollection<IPPacket> SelectedPacketTree { get; private set; }

        public ObservableCollection<string> DeviceAddressList { get; private set; }

        private string selectedAddress;
        public string SelectedAddress
        {
            get
            {
                return selectedAddress;
            }
            set
            {
                selectedAddress = value;
                RaisePropertyChanged("SelectedAddress");
            }
        }

        public string HexPacketData
        {
            get
            {
                try
                {
                    int length = SelectedPacket.IPHeader[0].TotalLength;

                    StringBuilder stringBuilder = new StringBuilder(length * 2);

                    // Copy header and message from selected IP packet to packetData
                    byte[] packetData = new byte[length];
                    Array.Copy(SelectedPacket.ByteIPHeader, packetData, SelectedPacket.ByteIPHeader.Length);
                    Array.Copy(SelectedPacket.ByteIPMessage, 0, packetData, SelectedPacket.ByteIPHeader.Length, SelectedPacket.ByteIPMessage.Length);

                    for (int i = 0; i < length; i++)
                    {
                        stringBuilder.Append(packetData[i].ToString("x2") + " ");
                    }

                    return stringBuilder.ToString();
                }
                catch
                {
                    return null;
                }
            }
        }

        public string CharPacketData
        {
            get
            {
                try {
                    int length = SelectedPacket.IPHeader[0].TotalLength;

                    StringBuilder stringBuilder = new StringBuilder();

                    // Copy header and message from selected IP packet to packetData
                    byte[] packetData = new byte[length];
                    Array.Copy(SelectedPacket.ByteIPHeader, packetData, SelectedPacket.ByteIPHeader.Length);
                    Array.Copy(SelectedPacket.ByteIPMessage, 0, packetData, SelectedPacket.ByteIPHeader.Length, SelectedPacket.ByteIPMessage.Length);

                    for (int i = 0; i < length; i++)
                    {
                        if (packetData[i] > 31 && packetData[i] < 128)
                            stringBuilder.Append((char)packetData[i]);
                        else
                            stringBuilder.Append(".");
                    }

                    return stringBuilder.ToString();
                }
                catch
                {
                    return null;
                }
            }
        }

        private string filterBox;
        public string FilterBox
        {
            get
            {
                return filterBox;
            }
            set
            {
                filterBox = value;
                RaisePropertyChanged("FilterBox");
            }
        }
        #endregion

        #region Methods
        private void GetAddresses()
        {
            IPHostEntry HostEntry = Dns.GetHostEntry(Dns.GetHostName());
            if (HostEntry.AddressList.Length > 0) {
                foreach (IPAddress ip in HostEntry.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        DeviceAddressList.Add(ip.ToString());
                    }
                }
            }
        }        

        private void ReceiveNewPacket(IPPacket newPacket)
        {
            newPacket.PacketID = (uint)PacketList.Count + 1;

            lock (PacketList)
            {
                PacketList.Add(newPacket);
            }

            lock (filteredPacketList)
            {
                AddToFilteredList(newPacket);
            }

            StatsHandler.UpdateStats(newPacket);
        }

        private void AddToFilteredList(IPPacket newPacket)
        {
            // If the filterString is empty, just add newPacket to the FilterPacketList
            if (String.IsNullOrEmpty(filter))
            {
                FilteredPacketList.Add(newPacket);
                return;
            }

            // Split filter into substrings and make it all uppercase
            filter = filter.ToUpper();
            List<string> filterList = new List<string>(filter.Split(' '));

            // List of IP addresses from src/dest syntax
            List<string> SrcIPList = new List<string>();
            List<string> DestIPList = new List<string>();

            // List of Ports from sp/dp syntax
            List<string> SrcPortList = new List<string>();
            List<string> DestPortList = new List<string>();

            // A list of allowed filters
            string[] allowedProtocols = { "UDP", "TCP", "IGMP", "ICMP", "DNS" };
            // After cleaning all the garbage, filterList should contain only strings
            // from allowedProtocols

            // Remove all substrings that are not in list of allowed filters
            // But if a substring is src/dest ip or sp/dp port, tranfser it to its List
            for (int i = filterList.Count - 1; i >= 0; i--)
            {
                // Next two If conditions will add IP addresses to IP Lists, if there are any
                if (filterList[i].Contains("SRC="))
                {
                    SrcIPList = ValidIPAddress(SrcIPList, filterList[i]);
                }
                else if (filterList[i].Contains("DEST="))
                {
                    DestIPList = ValidIPAddress(DestIPList, filterList[i]);
                }

                // Next two If conditions will add Ports to Port Lists, if there are any
                else if (filterList[i].Contains("SP="))
                {
                    SrcPortList = ValidPort(SrcPortList , filterList[i]);
                }
                else if (filterList[i].Contains("DP="))
                {
                    DestPortList = ValidPort(DestPortList , filterList[i]);
                }

                else
                {
                    // If substring is a protocol from AllowedProtocol list,
                    // don't remove it and continue
                    string[] check = Strings.Filter(allowedProtocols, filterList[i], true);
                    if (check != null && check.Length > 0)
                    {
                        continue;
                    }
                }
                // Cleaning the garbage
                filterList.RemoveAt(i);
            }

            // If none of the substrings uses the proper syntax, ignore it and add packet
            // as if there was no filter at all.
            if (filterList.Count == 0 && SrcIPList.Count == 0 && DestIPList.Count == 0 &&
                SrcPortList.Count == 0 && DestPortList.Count == 0)
            {
                FilteredPacketList.Add(newPacket);
                return;
            }

            bool ProtocolRule = true;
            foreach (string filterString in filterList)
            {
                ProtocolRule = false;
                if (filterString.Equals("UDP") && newPacket.UDPPacket.Count > 0)
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("TCP") && newPacket.TCPPacket.Count > 0)
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("IGMP") &&
                    newPacket.IPHeader[0].TransportProtocolName == "IGMP")
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("ICMP") &&
                    newPacket.IPHeader[0].TransportProtocolName == "ICMP")
                {
                    ProtocolRule = true;
                    break;
                }
                else if (filterString.Equals("DNS") && 
                    newPacket.UDPPacket.Count > 0 &&
                    (newPacket.UDPPacket[0].UDPHeader[0].DestinationPort == 53 ||
                    newPacket.UDPPacket[0].UDPHeader[0].SourcePort == 53))
                {
                    ProtocolRule = true;
                    break;
                }
            }

            bool SrcIPRule = true;
            foreach (string ip in SrcIPList)
            {
                SrcIPRule = false;
                if (ip == newPacket.IPHeader[0].SourceIPAddress.ToString())
                {
                    SrcIPRule = true;
                    break;
                }
            }

            bool DstIPRule = true;
            foreach (string ip in DestIPList)
            {
                DstIPRule = false;
                if (ip == newPacket.IPHeader[0].DestinationIpAddress.ToString())
                {
                    DstIPRule = true;
                    break;
                }
            }

            bool SrcPortRule = true;
            foreach (string port in SrcPortList)
            {
                SrcPortRule = false;
                if (newPacket.TCPPacket.Count > 0 &&
                    port == newPacket.TCPPacket[0].TCPHeader[0].SourcePort.ToString())
                {
                    SrcPortRule = true;
                    break;
                }
                else if (newPacket.UDPPacket.Count > 0 &&
                         port == newPacket.UDPPacket[0].UDPHeader[0].SourcePort.ToString()) 
                {
                    SrcPortRule = true;
                    break;
                }
            }

            bool DestPortRule = true;
            foreach (string port in DestPortList)
            {
                DestPortRule = false;
                if (newPacket.TCPPacket.Count > 0 &&
                    port == newPacket.TCPPacket[0].TCPHeader[0].DestinationPort.ToString())
                {
                    DestPortRule = true;
                    break;
                }
                else if (newPacket.UDPPacket.Count > 0 &&
                         port == newPacket.UDPPacket[0].UDPHeader[0].DestinationPort.ToString()) 
                {
                    DestPortRule = true;
                    break;
                }
            }

            if (ProtocolRule == true && SrcIPRule == true && DstIPRule == true &&
                SrcPortRule == true && DestPortRule == true)
            {
                FilteredPacketList.Add(newPacket);
            }
        }

        /// <summary>
        /// Returns the same List given in parameter list, but with new string
        /// if evaluated as valid
        /// </summary>
        /// <param name="IPList">List of IPs in which new IP will be stored</param>
        /// <param name="isValid">IP to be evaluated</param> 
        private List<string> ValidIPAddress(List<string> IPList, string isValid)
        {
            const string PatternIP = @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$";
            const string SrcPattern = @"^SRC=" + PatternIP;
            const string DstPattern = @"^DEST=" + PatternIP;

            if (Regex.Match(isValid, SrcPattern).Success ||
                Regex.Match(isValid, DstPattern).Success)
            {
                string ipString = Regex.Match(isValid, PatternIP).Value;
                IPAddress ipAddress;
                if (IPAddress.TryParse(ipString, out ipAddress))
                {
                    IPList.Add(ipString);
                }
            }

            return IPList;
        }

        /// <summary>
        /// Returns the same List given in parameter list, but with new string
        /// if evaluated as valid
        /// </summary>
        /// <param name="IPList">List of Ports in which new Port will be stored</param>
        /// <param name="isValid">Port to be evaluated</param> 
        private List<string> ValidPort(List<string> PortList, string isValid)
        {
            const string PatternPort = @"\d{1,5}$";
            const string SrcPattern = @"^SP=" + PatternPort;
            const string DstPattern = @"^DP=" + PatternPort;

            if (Regex.Match(isValid, SrcPattern).Success ||
                Regex.Match(isValid, DstPattern).Success)
            {
                string PortString = Regex.Match(isValid, PatternPort).Value;
                ushort usPort;
                if (UInt16.TryParse(PortString, out usPort))
                {
                    PortList.Add(PortString);
                }
            }

            return PortList;
        }

        private void FilterAllPackets()
        {
            // To filter all packets, we must refresh the whole list
            FilteredPacketList.Clear();

            lock (PacketList)
            {
                foreach (IPPacket packet in PacketList)
                {
                    lock (FilteredPacketList)
                    {
                        AddToFilteredList(packet);
                    }
                }
            }

            // This condition here avoids threading problem:
            //   If a new packet is captured just before FilterAllPackets() is called, 
            //   this removes all newPackets that arrived before this function call.
            while (FilteredPacketList.Count > 2)
            {
                uint firstPacketID = filteredPacketList[0].PacketID;
                uint lastPacketID = filteredPacketList[filteredPacketList.Count - 2].PacketID;

                if (firstPacketID > lastPacketID)
                {
                    filteredPacketList.RemoveAt(0);
                    continue;
                }
                break;
            }
        }
        #endregion

        #region Commands
        public ICommand OpenAnalyzer { get; private set; }
        
        private void OpenAnalyzerExecute()
        {
            CurrentViewModel = analyzerViewModel;
        }

        public ICommand OpenSniffer { get; private set; }

        private void OpenSnifferExecute()
        {
            CurrentViewModel = snifferViewModel;
        }

        public ICommand OpenHelp { get; private set; }

        private void OpenHelpExecute()
        {
            CurrentViewModel = helpViewModel;
        }

        public ICommand StartCapture { get; private set; }

        private void StartCaptureExecute()
        {
            if (string.IsNullOrEmpty(SelectedAddress))
            {
                MessageBox.Show("Please select device address");
            }
            else if (!UserIdentityHandler.IsUserAdministrator())
            {
                MessageBox.Show("Please start program with administrator privileges");
            }
            else
            {
                if (monitor == null ) {
                    monitor = new InterfaceMonitor(SelectedAddress);
                    monitor.newPacketEventHandler += new InterfaceMonitor.NewPacketEventHandler(ReceiveNewPacket);
                    monitor.StartCapture();
                    StatsHandler.Timer.Start();
                    StatsHandler.CaptureStartTime = DateTime.Now;
                }
            }
        }

        public ICommand StopCapture { get; private set; }

        private void StopCaputureExecute()
        {
            if (monitor != null)
            {
                monitor.StopCapture();
                monitor = null;
                StatsHandler.Timer.Stop();
            }
        }

        public ICommand ClearPacketList { get; private set; }

        private void ClearPacketListExecute()
        {
            PacketList.Clear();
            FilteredPacketList.Clear();
            filter = FilterBox;
            StatsHandler.Timer.Stop();

            if (monitor != null)
            {
                StatsHandler.CaptureStartTime = DateTime.Now;
                StatsHandler.Timer.Start();
            }
        }

        public ICommand ResetFilter { get; private set; }

        private void ResetFilterExecute()
        {
            FilterBox = "";
            filter = "";
            FilterAllPackets();
        }

        public ICommand ApplyFilter { get; private set; }

        private void ApplyFilterExecute()
        {
            filter = FilterBox;
            FilterAllPackets();
        }
        #endregion
    }
}