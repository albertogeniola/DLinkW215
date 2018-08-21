using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace DLinkW215
{
    /// <summary>
    /// Port of the pyW215 (https://github.com/LinuxChristian/pyW215)python library for controlling the DLink W215 smart plug.
    /// Credits to LinuxChristian for the good job.
    /// </summary>
    public class DLinkW215SmartPlug : IDisposable
    {
        public string Ip { get; private set; }
        public string Url { get; private set; }
        public string User { get; private set; }
        public string Password { get; private set; }
        public string ModelName { get; private set; }
        public bool LegacySupport { get; private set; }
        // Contains: [0] -> privatekey [1] -> cookie
        private string[] Authenticated { get; set; }

        private bool _errorReport;
        private CookieContainer _cookieContainer;
        private HttpClientHandler _httpClientHandler;
        private HttpClient _httpClient;

        public DLinkW215SmartPlug(string ip, string password, string user = "admin", bool legacySupport = false)
        {
            _cookieContainer = new CookieContainer();
            _httpClientHandler = new HttpClientHandler();
            _httpClientHandler.CookieContainer = _cookieContainer;
            _httpClient = new HttpClient(_httpClientHandler);
            Ip = ip;
            Url = string.Format("http://{0}/HNAP1/", Ip);
            User = user;
            Password = password;
            Authenticated = null;
            LegacySupport = legacySupport;
            
            var deviceSettings = SOAPAction("GetDeviceSettings");
            ModelName = GetResponseTagValue(deviceSettings, "ModelName");

            _errorReport = false;
        }

        public void Dispose()
        {
            if (_httpClientHandler != null)
            {
                _httpClientHandler.Dispose();
                _httpClientHandler = null;
            }

            if (_httpClient != null)
            {
                _httpClient.Dispose();
                _httpClient = null;
            }
        }

        private string SOAPAction(string action, string responseElementTagName, string parameters = "", bool recursive = false) {
            XmlDocument doc = SOAPAction(action, parameters, recursive);

            return GetResponseTagValue(doc, responseElementTagName);
        }

        private string GetResponseTagValue(XmlDocument doc, string responseElementTag) {
            // Get value from device
            string value = null;
            try
            {
                var valueArray = doc.GetElementsByTagName(responseElementTag);
                value = valueArray[0].InnerText;
            }
            catch (Exception e)
            {
                return null;
            }

            if (value == null && _errorReport == false)
            {
                _errorReport = true;
                return null;
            }

            _errorReport = false;
            return value;
        }

        private XmlDocument SOAPAction(string action, string parameters = "", bool recursive = false)
        {
            // Authenticate client
            if (Authenticated == null)
                Authenticated = Auth();

            var auth = Authenticated;

            // If not legacy protocol, ensure auth() is called for every call
            if (!LegacySupport)
                Authenticated = null;

            if (auth == null)
                return null;

            var payload = RequestBody(action, parameters);

            // Get the uinix timestamp in seconds
            var time_stamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            var action_url = string.Format("\"http://purenetworks.com/HNAP1/{0}\"", action);
            var AUTHKey = HmacMd5(auth[0], (time_stamp + action_url)).ToUpper() + " " + time_stamp;

            var payloadContent = new StringContent(payload, Encoding.UTF8);
            payloadContent.Headers.ContentType = new MediaTypeHeaderValue("text/xml");
            payloadContent.Headers.Add("SOAPAction", string.Format("\"http://purenetworks.com/HNAP1/{0}\"", action));
            payloadContent.Headers.Add("HNAP_AUTH", AUTHKey);
            string responseString = null;

            try
            {
                var response = _httpClient.PostAsync(Url, payloadContent).GetAwaiter().GetResult();
                responseString = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                // Try to re-authenticate once
                Authenticated = null;
                XmlDocument return_value = null;
                if (!recursive)
                    return_value = SOAPAction(action, parameters, true);
                if (recursive || return_value == null)
                {
                    _errorReport = true;
                    return null;
                }
                else
                    return return_value;
            }

            XmlDocument doc = new XmlDocument();
            doc.LoadXml(responseString);
            return doc;
        }

        private static string HmacMd5(string key, string text)
        {
            using (HMACMD5 hmac = new HMACMD5(Encoding.UTF8.GetBytes(key)))
            {
                byte[] hashValue = hmac.ComputeHash(Encoding.UTF8.GetBytes(text));
                return BitConverter.ToString(hashValue).Replace("-", "");
            }
        }

        /// <summary>
        /// Returns the request payload for an action as XML
        /// </summary>
        /// <param name="action">Which action to perform</param>
        /// <param name="parameters">Any parameters required for request</param>
        /// <returns>XML payload for request</returns>
        private string RequestBody(string action, string parameters)
        {
            return string.Format("\"<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><{0} xmlns=\"http://purenetworks.com/HNAP1/\">{1}</{0}></soap:Body></soap:Envelope>", action, parameters);
        }

        /// <summary>
        /// Authenticate using the SOAP interface.
        /// Authentication is a two-step process.First a initial payload
        /// is sent to the device requesting additional login information in the form
        /// of a publickey, a challenge string and a cookie.
        /// These values are then hashed by a MD5 algorithm producing a privatekey
        /// used for the header and a hashed password for the XML payload.
        /// If everything is accepted the XML returned will contain a LoginResult tag with the
        /// string 'success'.
        /// See https://github.com/bikerp/dsp-w215-hnap/wiki/Authentication-process for more information.
        /// </summary>
        /// <returns></returns>
        private string[] Auth()
        {
            var payload = InitialAuthPayload();

            // Build initial header
            var payloadContent1 = new StringContent(payload, Encoding.UTF8);
            payloadContent1.Headers.ContentType = new MediaTypeHeaderValue("text/xml");
            payloadContent1.Headers.Add("SOAPAction", "\"http://purenetworks.com/HNAP1/Login\"");

            // Request privatekey, cookie and challenge
            string xmlData = null;
            try
            {
                var response1 = _httpClient.PostAsync(Url, payloadContent1).GetAwaiter().GetResult();
                xmlData = response1.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                if (_errorReport == false)
                {
                    _errorReport = true;
                }
                return null;
            }

            XmlDocument root = new XmlDocument();
            root.LoadXml(xmlData);

            // Find responses
            var challengeEl = root.GetElementsByTagName("Challenge");//[0].InnerText;
            var cookieEl = root.GetElementsByTagName("Cookie");//[0].InnerText;
            var publickeyEl = root.GetElementsByTagName("PublicKey");//[0].InnerText;

            if ((challengeEl.Count == 0 || cookieEl.Count == 0 || publickeyEl.Count == 0) && _errorReport == false)
            {
                _errorReport = true;
                return null;
            }

            var challenge = challengeEl[0].InnerText;
            var cookie = cookieEl[0].InnerText;
            var publickey = publickeyEl[0].InnerText;


            // Generate hash responses
            var privateKey = HmacMd5(publickey + Password, challenge).ToUpper();
            var login_pwd = HmacMd5(privateKey, challenge).ToUpper();

            var response_payload = AuthPayload(login_pwd);

            // Build response to request
            var payloadContent = new StringContent(response_payload, Encoding.UTF8);
            payloadContent.Headers.ContentType = new MediaTypeHeaderValue("text/xml");
            payloadContent.Headers.Add("SOAPAction", "\"http://purenetworks.com/HNAP1/Login\"");
            payloadContent.Headers.Add("HNAP_AUTH", string.Format("\"{0}\"", privateKey));

            _cookieContainer.SetCookies(new Uri(Url), string.Format("uid={0}", cookie));

            var response = _httpClient.PostAsync(Url, payloadContent).GetAwaiter().GetResult();
            xmlData = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            root = new XmlDocument();
            root.LoadXml(xmlData);

            // Find responses
            var login_status = root.GetElementsByTagName("LoginResult")[0].InnerText.ToLower();

            if (login_status != "success" && _errorReport == false)
            {
                _errorReport = true;
                return null;
            }

            _errorReport = false; // Reset error logging
            return new string[] { privateKey, cookie };
        }

        /// <summary>
        /// Return the initial authentication payload.
        /// </summary>
        /// <returns></returns>
        private string InitialAuthPayload()
        {
            return "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Login xmlns=\"http://purenetworks.com/HNAP1/\"><Action>request</Action><Username>admin</Username><LoginPassword/><Captcha/></Login></soap:Body></soap:Envelope>";
        }

        /// <summary>
        /// Generate a new payload containing generated hash information.
        /// </summary>
        /// <param name="loginPassword">hashed password generated by the auth function.</param>
        /// <returns></returns>
        private string AuthPayload(string loginPassword)
        {
            string payload = string.Format("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Login xmlns = \"http://purenetworks.com/HNAP1/\"><Action>login</Action><Username>{0}</Username><LoginPassword>{1}</LoginPassword><Captcha/></Login></soap:Body></soap:Envelope>", User, loginPassword);
            return payload;
        }

        /// <summary>
        /// Returns moduleID XML.
        /// </summary>
        /// <param name="module"></param>
        /// <returns>XML string with moduleID</returns>
        private string ModuleParameters(string module)
        {
            return string.Format("<ModuleID>{0}</ModuleID>", module);
        }

        /// <summary>
        /// Returns control parameters as XML.
        /// </summary>
        /// <param name="module">The module number / ID</param>
        /// <param name="status">The state to set(i.e. true(on) or false(off))</param>
        /// <returns>XML string to join with payload</returns>
        private string ControlParameters(string module, string status)
        {
            if (LegacySupport)
                return string.Format("{0}<NickName>Socket 1</NickName><Description>Socket 1</Description><OPStatus>{1}</OPStatus><Controller>1</Controller>", ModuleParameters(module), status);
            else
                return string.Format("{0}<NickName>Socket 1</NickName><Description>Socket 1</Description><OPStatus>{1}</OPStatus>", ModuleParameters(module), status);
        }

        /// <summary>
        /// Returns RadioID as XML.
        /// </summary>
        /// <param name="radio">Radio number/ ID</param>
        /// <returns></returns>
        private string RadioParameters(string radio)
        {
            return string.Format("<RadioID>{0}</RadioID>", radio);
        }

        /// <summary>
        /// Fetches statistics from my_cgi.cgi
        /// </summary>
        /// <returns></returns>
        private Dictionary<string, string> FetchMyCgi()
        {
            Dictionary<string, string> res = new Dictionary<string, string>();
            try
            {
                var destUrl = string.Format("http://{0}/my_cgi.cgi", Ip);
                var data = new Dictionary<string, string>();
                data.Add("request", "create_chklst");
                var payloadContent = new FormUrlEncodedContent(data);
                var response = _httpClient.PostAsync(destUrl, payloadContent).GetAwaiter().GetResult();
                var stringResp = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                foreach (string line in stringResp.Split('\n'))
                {
                    var tokens = line.Split(':');
                    res[tokens[0].Trim()] = tokens[1].Trim();
                }
                return res;
            }
            catch (Exception e)
            {
                _errorReport = true;
                return null;
            }
        }

        public XmlDocument GetRawDeviceSettings()
        {
            var doc = SOAPAction("GetDeviceSettings");
            return doc;
        }

        /// <summary>
        /// Get the current power consumption in Watt.
        /// </summary>
        /// <returns></returns>
        public double? GetCurrentConsumption()
        {
            double? res = null;
            string textRes = null;

            try
            {
                // Use /my_cgi.cgi to retrieve current consumption
                if (LegacySupport)
                    textRes = FetchMyCgi()["Meter Watt"];
                else
                    textRes = SOAPAction("GetCurrentPowerConsumption", "CurrentConsumption", ModuleParameters("2"));
            }
            catch (Exception e)
            {
                return null;
            }

            if (textRes == null)
                return null;

            if (double.TryParse(textRes, System.Globalization.NumberStyles.Any, CultureInfo.InvariantCulture, out var parsedValue))
            {
                return parsedValue;
            }
            else
            {
                // What should we do here?
            }

            return res;
        }

        /// <summary>
        /// Get the total power consumpuntion in the device lifetime.
        /// </summary>
        /// <returns></returns>
        public double? GetTotalConsumption()
        {
            if (LegacySupport)
            {
                // TotalConsumption currently fails on the legacy protocol and
                // creates a mess in the logs. Just return 'N/A' for now.
                return null;
            }

            string textRes = null;
            try
            {
                textRes = SOAPAction("GetPMWarningThreshold", "TotalConsumption", ModuleParameters("2"));
            }
            catch (Exception ex)
            {
                return null;
            }

            if (textRes == null)
                return null;
            try
            {
                return double.Parse(textRes, NumberStyles.Any, CultureInfo.InvariantCulture);
            }
            catch (FormatException ex)
            {
                //_LOGGER.error("Failed to retrieve total power consumption from SmartPlug")
                return null;
            }
        }

        /// <summary>
        /// Get the device temperature in celsius.
        /// </summary>
        /// <returns></returns>
        public double? GetTemperature()
        {
            try
            {
                string textres = SOAPAction("GetCurrentTemperature", "CurrentTemperature", ModuleParameters("3"));
                return double.Parse(textres, NumberStyles.Any, CultureInfo.InvariantCulture);
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        /// <summary>
        /// Get the device state (i.e. ON or OFF).
        /// </summary>
        /// <returns></returns>
        public SwitchState GetState()
        {
            var response = SOAPAction("GetSocketSettings", "OPStatus", ModuleParameters("1"));
            if (response == null)
                return SwitchState.Unknown;
            else if (response.ToLower() == "true")
                return SwitchState.On;
            else if (response.ToLower() == "false")
                return SwitchState.Off;
            else
            {
                //_LOGGER.warning("Unknown state %s returned" % str(response.lower()))
                return SwitchState.Unknown;
            }
        }

        /// <summary>
        /// """Set device state.
        /// </summary>
        /// <param name="state">Future state(either ON or OFF)</param>
        public void SetState(SwitchState state)
        {
            switch (state)
            {
                case SwitchState.On:
                    SOAPAction("SetSocketSettings", "SetSocketSettingsResult", ControlParameters("1", "true"));
                    break;
                case SwitchState.Off:
                    SOAPAction("SetSocketSettings", "SetSocketSettingsResult", ControlParameters("1", "false"));
                    break;
                default:
                    throw new Exception(string.Format("State {0} is not valid", state));
            }
        }

        public enum SwitchState
        {
            On,
            Off,
            Unknown
        }
    }
}
