using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OAuth;
using System.Web;
using System.Net;
using System.IO;
using System.Diagnostics;
using System.Threading;

namespace Withings
{
    class Program
    {
        private const string consumerKey = "b2d497e82f8b1625919ed02e34c33d945bd3800f4e0b758d3c09341d5588f2";
        private const string consumerSecret = "1b670b04013cc0f5243bdd79846cc42cfe2f4b536c9b614e17d33b0d61f090";

        private class OAuthToken
        {
            public OAuthToken(string token, string secret, string userid)
            {
                Token = token;
                Secret = secret;
                UserID = userid;
            }

            public string Token { get; private set; }
            public string UserID { get; private set; }
            public string Secret { get; private set; }
        }


        private static OAuthToken GetRequestToken()
        {
            var uri = new Uri("http://oauth.withings.com/account/request_token");

            // Generate a signature
            OAuthBase oAuth = new OAuthBase();
            string nonce = oAuth.GenerateNonce();
            string timeStamp = oAuth.GenerateTimeStamp();
            string parameters;
            string normalizedUrl;
            string signature = oAuth.GenerateSignature(uri, consumerKey, consumerSecret,
                String.Empty, String.Empty, "GET", timeStamp, nonce, OAuthBase.SignatureTypes.HMACSHA1,
                out normalizedUrl, out parameters);

            signature = HttpUtility.UrlEncode(signature);

            StringBuilder requestUri = new StringBuilder(uri.ToString());
            requestUri.AppendFormat("?oauth_consumer_key={0}&", consumerKey);
            requestUri.AppendFormat("oauth_nonce={0}&", nonce);
            requestUri.AppendFormat("oauth_signature={0}&", signature);
            requestUri.AppendFormat("oauth_signature_method={0}&", "HMAC-SHA1");
            requestUri.AppendFormat("oauth_timestamp={0}&", timeStamp);
            requestUri.AppendFormat("oauth_version={0}", "1.0");

            var request = (HttpWebRequest)WebRequest.Create(new Uri(requestUri.ToString()));
            request.Method = WebRequestMethods.Http.Get;

            var response = request.GetResponse();

            var queryString = new StreamReader(response.GetResponseStream()).ReadToEnd();

            var parts = queryString.Split('&');
            //var token = parts[1].Substring(parts[1].IndexOf('=') + 1);
            //var secret = parts[0].Substring(parts[0].IndexOf('=') + 1);

            int index1 = 12;
            int index2 = 19;
            var token = parts[0].Substring(index1);
            var secret = parts[1].Substring(index2);
            var userid = "";

            return new OAuthToken(token, secret, userid);
        }

        private static OAuthToken GetAccessToken(OAuthToken oauthToken)
        {
            var uri = "http://oauth.withings.com/account/access_token";

            OAuthBase oAuth = new OAuthBase();

            //var nonce = oAuth.GenerateNonce();           
            var nonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString()));

            var timeStamp = oAuth.GenerateTimeStamp();
            string parameters;
            string normalizedUrl;
            var signature = oAuth.GenerateSignature(new Uri(uri), consumerKey, consumerSecret,
                oauthToken.Token, oauthToken.Secret, "GET", timeStamp, nonce,
                OAuthBase.SignatureTypes.HMACSHA1, out normalizedUrl, out parameters);

            signature = HttpUtility.UrlEncode(signature);

            var requestUri = new StringBuilder(uri);
            requestUri.AppendFormat("?oauth_consumer_key={0}&", consumerKey);
            requestUri.AppendFormat("oauth_nonce={0}&", nonce);
            requestUri.AppendFormat("oauth_signature={0}&", signature);
            requestUri.AppendFormat("oauth_signature_method={0}&", "HMAC-SHA1");
            requestUri.AppendFormat("oauth_timestamp={0}&", timeStamp);
            requestUri.AppendFormat("oauth_token={0}&", oauthToken.Token);
            requestUri.AppendFormat("oauth_version={0}", "1.0");

            var request = (HttpWebRequest)WebRequest.Create(requestUri.ToString());
            request.Method = WebRequestMethods.Http.Get;

            var response = request.GetResponse();
            var reader = new StreamReader(response.GetResponseStream());
            var accessToken = reader.ReadToEnd();

            var parts = accessToken.Split('&');
            //var token = parts[0].Substring(parts[0].IndexOf('=') + 1);
            //var secret = parts[1].Substring(parts[1].IndexOf('=') + 1);

            int index1 = 12;
            int index2 = 19;
            int index3 = 7;
            var token = parts[0].Substring(index1);
            var secret = parts[1].Substring(index2);
            var userID = parts[2].Substring(index3);

            return new OAuthToken(token, secret, userID);
        }

        static void Main(string[] args)
        {

            //Don't have token and token secret

            // Step 1/3: Get request token
            OAuthToken oauthToken = GetRequestToken();

            // Step 2/3: Authorize application
            var queryString = String.Format("oauth_token={0}", oauthToken.Token);
            var authorizeUrl = "http://oauth.withings.com/account/authorize?" + queryString;
            Process.Start(authorizeUrl);
            Thread.Sleep(5000); // Leave some time for the authorization step to complete

            // Step 3/3: Get access token
            OAuthToken accessToken = GetAccessToken(oauthToken);

            Console.WriteLine(String.Format("Your access token: {0}", accessToken.Token));
            Console.WriteLine(String.Format("Your access secret: {0}", accessToken.Secret));



            //Already have a token and token secret
            var OAuthTokenKey = accessToken.Token;
            var OAuthTokenSecretKey = accessToken.Secret;
            var UserID = accessToken.UserID;

            //ConfigurationManager.AppSettings["key"]
            //var uri = "http://wbsapi.withings.net/user?action=getbyuserid&userid=UserID";
            //var uri = "http://wbsapi.withings.net/measure?action=getmeas&userid=29&startdate=1222819200&enddate=1223190167";
            //var uri = "http://wbsapi.withings.net/v2/measure?action=getactivity&userid=29&date=2014-05-05";
            var uri = "http://wbsapi.withings.net/v2/measure?action=getactivity&userid=2054891&startdateymd=2013-10-04&enddateymd=2014-05-05";
            //var uri = "http://wbsapi.withings.net/notify?action=get&userid=2054891&callbackurl=http%3a%2f%2fmedlab.cc.uoi.gr";
            //var uri = "http://wbsapi.withings.net/notify?action=list&userid=2054891";

            //var OAuthTokenKey = "855bcb9109b4244eec18196935fc550ff0be71c7313745d1ccdb47f62957";
            //var OAuthTokenSecretKey = "4c35f0b1cb9236be820940315e84957260db5e17eff7087f715f703591f69b";
            //var userid = "2054891";

            OAuthBase oAuth = new OAuthBase();

            //var nonce = oAuth.GenerateNonce();           
            var nonce = Convert.ToBase64String(new ASCIIEncoding().GetBytes(DateTime.Now.Ticks.ToString()));

            var timeStamp = oAuth.GenerateTimeStamp();
            string parameters;
            string normalizedUrl;
            var signature = oAuth.GenerateSignature(new Uri(uri), consumerKey, consumerSecret,
                OAuthTokenKey, OAuthTokenSecretKey, "GET", timeStamp, nonce,
                OAuthBase.SignatureTypes.HMACSHA1, out normalizedUrl, out parameters);

            signature = HttpUtility.UrlEncode(signature);

            var requestUri = new StringBuilder(uri);
            requestUri.AppendFormat("&oauth_consumer_key={0}&", consumerKey);
            requestUri.AppendFormat("oauth_nonce={0}&", nonce);
            requestUri.AppendFormat("oauth_signature={0}&", signature);
            requestUri.AppendFormat("oauth_signature_method={0}&", "HMAC-SHA1");
            requestUri.AppendFormat("oauth_timestamp={0}&", timeStamp);
            requestUri.AppendFormat("oauth_token={0}&", OAuthTokenKey);
            requestUri.AppendFormat("oauth_version={0}", "1.0");


            Process.Start(requestUri.ToString());

            Console.WriteLine();
            Console.WriteLine("Press any key to continue...");
            Console.ReadKey();

        }
    }
}
