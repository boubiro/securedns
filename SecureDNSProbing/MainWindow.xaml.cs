using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Threading;
using System.IO;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Xml.XPath;
using System.Xml.Linq;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace SecureDNSProbing
{
    [DataContract]
    public class AnswerStruct
    {
        [DataMember(Name = "name")]
        public string name { get; protected set; }
        [DataMember(Name = "type")]
        public int type { get; protected set; }
        [DataMember(Name = "TTL")]
        public int TTL { get; protected set; }
        [DataMember(Name = "data")]
        public string data { get; protected set; }
    }
    [DataContract]
    public class GoogleDNSResponse
    {
        [DataMember(Name = "Status")]  // Standard DNS response code (32 bit integer)
        public int status { get; protected set; }
        [DataMember(Name = "TC")]  // Whether the response is truncated
        public bool tc { get; protected set; }
        [DataMember(Name = "RD")]
        public bool rd { get; protected set; }
        [DataMember(Name = "RA")]
        public bool ra { get; protected set; }
        [DataMember(Name = "AD")]  // Whether all response data was validated with DNSSEC
        public bool ad { get; protected set; }
        [DataMember(Name = "CD")]  // Whether the client asked to disable DNSSEC
        public bool cd { get; protected set; }
        [DataMember(Name = "Answer")]
        public AnswerStruct[] answer { get; protected set; }
    }

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
        private volatile bool _shouldStop = false;
        private volatile int intTotal = 0;
        private volatile int intSuccess = 0;

        private string[] endpoints = { "https://dns.google.com/resolve?type=1&name=",
                                       "https://1.1.1.1/dns-query?ct=application/dns-json&type=A&name=",
                                       "https://1.0.0.1/dns-query?ct=application/dns-json&type=A&name=" };

        private bool CheckIfDomainExist(string strDomainName, int endpointIndex, out bool isAD, ref string ip)
        {
            string strURLBase = endpoints[endpointIndex];
            WebRequest request = WebRequest.Create(strURLBase + strDomainName);
            WebResponse response = request.GetResponse();
            if (((HttpWebResponse)response).StatusCode != HttpStatusCode.OK)
            {
                throw new WebException("Status is not 200");
            }
            StreamReader stream = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
            string strResponse = stream.ReadToEnd();

            GoogleDNSResponse dns = new GoogleDNSResponse();
            MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(strResponse));
            DataContractJsonSerializer ser = new DataContractJsonSerializer(dns.GetType());
            dns = ser.ReadObject(ms) as GoogleDNSResponse;
            ms.Close();
            isAD = dns.ad;
            if (dns.status == 0)
            {
                if (dns.answer != null && dns.answer[0] != null)
                {
                    for (int i = 0; i < dns.answer.Length; i++)
                    {
                        if (i > 0) ip += ", ";
                        ip += dns.answer[i].data;
                    }
                    
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else if (dns.status == 3 || dns.status == 2)
            {
                return false; // 2: Server failed, 3: NXDomain
            }
            else
            {
                throw new Exception("DNS Status Code for domain " + strDomainName + " is " + dns.status.ToString());
            }
        }

        private void ProcessDomain(string strTopDomain, int intEndpointIndex)
        {
            string[] arrSuffix;
            try
            {
                arrSuffix = System.IO.File.ReadAllLines("subdomaindictionary.txt");
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            try
            {
                bool isAD;
                string ip = "";
                CheckIfDomainExist(strTopDomain, intEndpointIndex, out isAD, ref ip);
                this.Dispatcher.Invoke(new Action(
                    delegate ()
                    {
                        txtResults.AppendText("DNSSEC is " + (isAD ? "" : "not ") + "enabled for this domain.\r\n");   
                    }
                ));
                if (CheckIfDomainExist("sdkjoi3wrsdklfjiwoa1o2p4." + strTopDomain, intEndpointIndex, out isAD, ref ip))
                {
                    if (CheckIfDomainExist("jdfolsq2319al11slfos." + strTopDomain, intEndpointIndex, out isAD, ref ip))
                    {
                        MessageBox.Show(strTopDomain + " uses wildcard DNS resolving.", "Can't determine subdomains", MessageBoxButton.OK, MessageBoxImage.Information);
                        return;
                    }
                }
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            int i = 0;

            while (!_shouldStop && i < arrSuffix.Length)
            {
                string strFullDomain = arrSuffix[i] + "." + strTopDomain;
                bool isSuccess = false;
                bool isAD;
                string ip = "";
                try
                {
                    isSuccess = CheckIfDomainExist(strFullDomain, intEndpointIndex, out isAD, ref ip);
                }
                catch(Exception e)
                {
                    MessageBox.Show(e.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
                
                intTotal++;
                this.Dispatcher.Invoke(new Action(
                    delegate ()
                    {
                        txtNumTests.Text = intTotal.ToString();
                        if (isSuccess)
                        {
                            intSuccess++;
                            txtResults.AppendText(strFullDomain + ": " + ip + "\r\n");
                            txtNumSubdomains.Text = intSuccess.ToString();
                        }
                    }));
                i++;
                Thread.Sleep(50);
            }
            string strAllResults = "";
            this.Dispatcher.Invoke(new Action(
                delegate ()
                {
                    strAllResults = txtResults.Text;
                }));
            try
            {
                if (!Directory.Exists("DNSResults"))
                {
                    Directory.CreateDirectory("DNSResults");
                }
                DateTime time = DateTime.Now;
                string timestamp = time.ToString("yyyy-MM-dd hh-mm-ss");
                File.WriteAllText("DNSResults\\" + strTopDomain + " " + timestamp + ".txt", strAllResults);
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "Cannot save results", MessageBoxButton.OK, MessageBoxImage.Asterisk);
            }
        }

        private void ThreadProc()
        {
            string strDomain = "";
            int intEndpointIndex = 0;
            
            this.Dispatcher.Invoke(new Action(
                delegate ()
                {
                    strDomain = txtDomain.Text;
                    if (rbCF1.IsChecked == true)
                        intEndpointIndex = 1;
                    else if (rbCF2.IsChecked == true)
                        intEndpointIndex = 2;
                }));
            ProcessDomain(strDomain, intEndpointIndex);
            this.Dispatcher.Invoke(new Action(
                delegate ()
                {
                    btnStop.IsEnabled = false;
                    btnGo.IsEnabled = true;
                    rbGoogle.IsEnabled = true;
                    rbCF1.IsEnabled = true;
                    rbCF2.IsEnabled = true;
                }));
        }

        private void Button_Go_Click(object sender, RoutedEventArgs e)
        {
            _shouldStop = false;
            intTotal = 0;
            intSuccess = 0;
            txtResults.Text = "";
            txtNumSubdomains.Text = "0";
            txtNumTests.Text = "0";
            btnStop.IsEnabled = true;
            btnGo.IsEnabled = false;
            rbGoogle.IsEnabled = false;
            rbCF1.IsEnabled = false;
            rbCF2.IsEnabled = false;
            Thread thread = new Thread(new ThreadStart(ThreadProc));
            thread.Start();
        }

        private void Button_Stop_Click(object sender, RoutedEventArgs e)
        {
            _shouldStop = true;
            btnStop.IsEnabled = false;
        }

        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Environment.Exit(0);
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            txtDomain.Focus();
        }
    }
}
