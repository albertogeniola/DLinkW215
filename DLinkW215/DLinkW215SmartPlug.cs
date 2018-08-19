using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
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
    public class DLinkW215SmartPlug
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

        public DLinkW215SmartPlug(string ip, string password, string user = "admin", bool legacySupport = false)
        {
            _cookieContainer = new CookieContainer();
            Ip = ip;
            Url = string.Format("http://{0}/HNAP1/", Ip);
            User = user;
            Password = password;
            Authenticated = null;
            LegacySupport = legacySupport;
            ModelName = SOAPAction("GetDeviceSettings", "ModelName", "");
            _errorReport = false;
        }

        private string SOAPAction(string action, string responseElement, string parameters = "", bool recursive = false)
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

            var request = WebRequest.CreateHttp(Url);
            request.CookieContainer = _cookieContainer;
            byte[] data = Encoding.UTF8.GetBytes(payload);
            request.Method = "POST";
            request.ContentLength = data.Length;
            request.ContentType = "\"text/xml; charset=utf-8\"";
            request.Headers["SOAPAction"] = string.Format("\"http://purenetworks.com/HNAP1/{0}\"", action);
            request.Headers["HNAP_AUTH"] = AUTHKey;
            //request.CookieContainer.Add(new Cookie("uid", auth[1], "/", Ip));

            string responseString = null;

            try
            {
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }
                var response = (HttpWebResponse)request.GetResponse();
                responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
            }
            catch (Exception e)
            {
                // Try to re-authenticate once
                Authenticated = null;

                // Recursive call to retry action
                string return_value = null;
                if (!recursive)
                    return_value = SOAPAction(action, responseElement, parameters, true);
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

            // Get value from device
            string value = null;
            try
            {
                var valueArray = doc.GetElementsByTagName(responseElement);
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
            var request = WebRequest.CreateHttp(Url);
            byte[] data1 = Encoding.UTF8.GetBytes(payload);
            request.Method = "POST";
            request.ContentLength = data1.Length;
            request.ContentType = "\"text/xml; charset=utf-8\"";
            request.Headers["SOAPAction"] = "\"http://purenetworks.com/HNAP1/Login\"";

            // Request privatekey, cookie and challenge
            string xmlData = null;
            try
            {
                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data1, 0, data1.Length);
                }
                var response1 = (HttpWebResponse)request.GetResponse();
                xmlData = new StreamReader(response1.GetResponseStream()).ReadToEnd();

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

            // Build response to initial request
            var challengeResponseRequest = WebRequest.CreateHttp(Url);
            byte[] data = Encoding.UTF8.GetBytes(response_payload);
            challengeResponseRequest.ContentLength = data.Length;
            challengeResponseRequest.Method = "POST";

            challengeResponseRequest.CookieContainer = _cookieContainer;
            challengeResponseRequest.ContentType = "\"text/xml; charset=utf-8\"";
            challengeResponseRequest.Headers["SOAPAction"] = "\"http://purenetworks.com/HNAP1/Login\"";
            challengeResponseRequest.Headers["HNAP_AUTH"] = string.Format("\"{0}\"", privateKey);
            challengeResponseRequest.CookieContainer.SetCookies(new Uri(Url), string.Format("uid={0}", cookie));

            using (var stream = challengeResponseRequest.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }
            var response = (HttpWebResponse)challengeResponseRequest.GetResponse();
            xmlData = new StreamReader(response.GetResponseStream()).ReadToEnd();
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
                var request = WebRequest.CreateHttp(destUrl);
                byte[] data = Encoding.UTF8.GetBytes("request=create_chklst");
                request.ContentLength = data.Length;
                request.Method = "POST";

                using (var stream = request.GetRequestStream())
                {
                    stream.Write(data, 0, data.Length);
                }
                var response = (HttpWebResponse)request.GetResponse();
                var stringResp = new StreamReader(response.GetResponseStream());
                string line = null;
                while ((line = stringResp.ReadLine()) != null) {
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
        public double? GetTotalConsumption() {
            if (LegacySupport) {
                // TotalConsumption currently fails on the legacy protocol and
                // creates a mess in the logs. Just return 'N/A' for now.
                return null;
            }

            string textRes = null;
            try
            {
                textRes = SOAPAction("GetPMWarningThreshold", "TotalConsumption", ModuleParameters("2"));
            } catch (Exception ex) {
                return null;
            }

            if (textRes == null)
                return null;
            try
            {
                return double.Parse(textRes, NumberStyles.Any, CultureInfo.InvariantCulture);
            } catch (FormatException ex) {
                //_LOGGER.error("Failed to retrieve total power consumption from SmartPlug")
                return null;
            }
        }

        /// <summary>
        /// Get the device temperature in celsius.
        /// </summary>
        /// <returns></returns>
        public double? GetTemperature() {
            try
            {
                string textres = SOAPAction("GetCurrentTemperature", "CurrentTemperature", ModuleParameters("3"));
                return double.Parse(textres, NumberStyles.Any, CultureInfo.InvariantCulture);
            } catch (Exception ex) {
                return null;
            }
        }

        /// <summary>
        /// Get the device state (i.e. ON or OFF).
        /// </summary>
        /// <returns></returns>
        public SwitchState GetState() {
            var response = SOAPAction("GetSocketSettings", "OPStatus", ModuleParameters("1"));
            if (response == null)
                return SwitchState.Unknown;
            else if (response.ToLower() == "true")
                return SwitchState.On;
            else if (response.ToLower() == "false")
                return SwitchState.Off;
            else {
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

        public enum SwitchState {
            On,
            Off,
            Unknown
        }
    }
}
