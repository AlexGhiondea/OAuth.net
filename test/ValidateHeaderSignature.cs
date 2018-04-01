using System;
using System.Net.Http;
using Xunit;

namespace OAuth.Net.Tests
{
    public class ValidateHeaderSignature
    {
        [Fact]
        public void ValidateSignature1()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    "http://www.foo.com/"),
                "d63f7c3ecbcb4b63950c1a418a8d68ce",
                "1522478039",
                OAuthVersion.OneZeroA);
            Assert.Equal("Q%2FzBeRiPDZFUdMQHJyIoD%2BmVxkk%3D", result);
        }
        [Fact]
        public void ValidateSignature2()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://www.foo.com/"),
                "ecc0248a5bb24049a12a2fd68b1fdd36",
                "1522478039",
                OAuthVersion.OneZeroA);
            Assert.Equal("FWTCA%2F0ecBYWJvv3ufnfsr9GCEk%3D", result);
        }
        [Fact]
        public void ValidateSignature3()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    "http://www.foo.com/?param1=value1"),
                "049d1506cea44b4d9f47d1507392c2f9",
                "1522478039",
                OAuthVersion.OneZeroA);
            Assert.Equal("K6IBBq0q7Nv1oac%2BF4SHw5OSSaU%3D", result);
        }
        [Fact]
        public void ValidateSignature4()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://www.foo.com/?param1=value1&param2=value2"),
                "ddfb04dbed154ac9aeade556c14202dc",
                "1522478039",
                OAuthVersion.OneZeroA);
            Assert.Equal("PazW%2FIVb6D%2Bsn5Z73z2jg79U8k8%3D", result);
        }
        [Fact]
        public void ValidateSignature5()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://www.foo.com/?param1=value1&param2&param3"),
                "5e93ad9588dc496fb0486a0110eeaea9",
                "1522478039",
                OAuthVersion.OneZeroA);
            Assert.Equal("jp%2F1Yh1cHd6yPDgX%2BsbHQV9ITNM%3D", result);
        }
        [Fact]
        public void ValidateSignature6()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://www.foo.com/?param1=value1&param2&param3&altParam=$34"),
                "a3d765e9e945436ea84b12273b136177",
                "1522478039",
                OAuthVersion.OneZeroA);
            Assert.Equal("vNBSSnUXEIw9NUEZay9%2FzgFlw10%3D", result);
        }
        [Fact]
        public void ValidateSignature7()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Post,
                    "https://www.foo.com/?Zed=one&Alpha&Beta"),
                "90e2ef68cf1c4949b7eb10eccbf28ded",
                "1522478309",
                OAuthVersion.OneZeroA);
            Assert.Equal("ixPe0T85xtBNamcPP4cvATsgVDE%3D", result);
        }
        [Fact]
        public void ValidateSignature8()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Post,
                    "https://www.foo.com/?Zed=one&Alpha-Is-Allowed&Beta"),
                "073e9812f10d4356bf0db6049ffc7673",
                "1522479777",
                OAuthVersion.OneZeroA);
            Assert.Equal("66iCpYzWSy6kb88J22ZBTjTSvks%3D", result);
        }
        [Fact]
        public void ValidateSignature9()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Post,
                    "https://www.foo.com/?These_Chars-are.Allowed~here"),
                "3ae4b47630c94faab2e51e3eb9220d56",
                "1522479777",
                OAuthVersion.OneZeroA);
            Assert.Equal("B3Rt%2Fz1ssytWlEB5WRVV%2F9nUoa0%3D", result);
        }
        [Fact]
        public void ValidateSignature10()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Post,
                    "https://www.foo.com/?Escape[these]parameters"),
                "b8b9b2080c0b4417a4309ba22df51a40",
                "1522479777",
                OAuthVersion.OneZeroA);
            Assert.Equal("iVmkZgBGLZDU99Sc1MezFnVP5FY%3D", result);
        }
        [Fact]
        public void ValidateSignature11()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Post,
                    "https://www.foo.com/?Escapeparameters{}"),
                "b3dffbfed3bf4777a27bb631c9910ae2",
                "1522479777",
                OAuthVersion.OneZeroA);
            Assert.Equal("EeNDJAVIIc1BzviHYP%2B7jAl6BDA%3D", result);
        }
        [Fact]
        public void ValidateSignature12()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Post,
                    "https://www.foo.com/?Escape[these]parameters{}"),
                "0f6093ebbee04aa4a9cf6c7e3a095702",
                "1522479777",
                OAuthVersion.OneZeroA);
            Assert.Equal("0eQCtR89OhlUPIBqku8PobHIFQA%3D", result);
        }
        [Fact]
        public void ValidateSignature13()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var request = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://www.foo.com/");

            request.Content = new StringContent(
                "param1=value1&param2&param3&altParam=$34",
                System.Text.Encoding.ASCII,
                "application/x-www-form-urlencoded");

            var result = th.ComputeOAuthSignature(
                request,
                "a3d765e9e945436ea84b12273b136177",
                "1522478039",
                OAuthVersion.OneZeroA);
            Assert.Equal("vNBSSnUXEIw9NUEZay9%2FzgFlw10%3D", result);
        }
        [Fact]
        public void ValidateSignature14()
        {
            TestHelper th = new TestHelper("1234", "4567", "234", "23424243243");
            var request = new HttpRequestMessage(
                    HttpMethod.Get,
                    "https://www.foo.com/?param1=value");

            request.Content = new StringContent(
                "param2&param3&altParam=$34",
                System.Text.Encoding.ASCII,
                "application/x-www-form-urlencoded");

            var result = th.ComputeOAuthSignature(
                request,
                "0f6093ebbee04aa4a9cf6c7e3a095702",
                "1522479777",
                OAuthVersion.OneZeroA);
        }
        [Fact]
        public void ValidateSignaturePerSpecExample()
        {
            TestHelper th = new TestHelper("dpf43f3p2l4k3l03", "kd94hf93k423kf44", "nnch734d00sl2jdk", "pfkkdhi9sl3r4s00");
            var result = th.ComputeOAuthSignature(
                new HttpRequestMessage(
                    HttpMethod.Get,
                    "http://photos.example.net/photos?file=vacation.jpg&size=original"),
                "kllo9940pd9333jh",
                "1191242096",
                OAuthVersion.OneZero); // the spec example uses 1.0 as the OAuth version.
            Assert.Equal("tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D", result);
        }
    }
}
