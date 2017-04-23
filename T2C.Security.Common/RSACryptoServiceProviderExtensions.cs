using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Xml;

namespace T2C.Security.Common
{
    public static class RSACryptoServiceProviderExtensions
        {
            public static string ExportPrivateKey(RSACryptoServiceProvider csp)
            {
                var outputStream = new StringWriter();
                if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
                var parameters = csp.ExportParameters(true);
                using (var stream = new MemoryStream())
                {
                    var writer = new BinaryWriter(stream);
                    writer.Write((byte)0x30); // SEQUENCE
                    using (var innerStream = new MemoryStream())
                    {
                        var innerWriter = new BinaryWriter(innerStream);
                        EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                        EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                        EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                        EncodeIntegerBigEndian(innerWriter, parameters.D);
                        EncodeIntegerBigEndian(innerWriter, parameters.P);
                        EncodeIntegerBigEndian(innerWriter, parameters.Q);
                        EncodeIntegerBigEndian(innerWriter, parameters.DP);
                        EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                        EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                        var length = (int)innerStream.Length;
                        EncodeLength(writer, length);
                        if (innerStream.TryGetBuffer(out ArraySegment<byte> innerBuffer))
                            writer.Write(innerBuffer.ToArray(), 0, length);
                    }
                    char[] base64 = { };
                    if (stream.TryGetBuffer(out ArraySegment<byte> outerBuffer))
                        base64 = Convert.ToBase64String(outerBuffer.ToArray(), 0, (int)stream.Length).ToCharArray();

                    outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
                    // Output as Base64 with lines chopped at 64 characters
                    for (var i = 0; i < base64.Length; i += 64)
                    {
                        outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                    }
                    outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
                    var toReturn = outputStream.ToString();
                    outputStream.Dispose();
                    return toReturn;
                }
            }

            public static string ExportPublicKey(RSACryptoServiceProvider csp)
            {
                var outputStream = new StringWriter();
                var parameters = csp.ExportParameters(false);
                using (var stream = new MemoryStream())
                {
                    var writer = new BinaryWriter(stream);
                    writer.Write((byte)0x30); // SEQUENCE
                    using (var innerStream = new MemoryStream())
                    {
                        var innerWriter = new BinaryWriter(innerStream);
                        innerWriter.Write((byte)0x30); // SEQUENCE
                        EncodeLength(innerWriter, 13);
                        innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                        var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                        EncodeLength(innerWriter, rsaEncryptionOid.Length);
                        innerWriter.Write(rsaEncryptionOid);
                        innerWriter.Write((byte)0x05); // NULL
                        EncodeLength(innerWriter, 0);
                        innerWriter.Write((byte)0x03); // BIT STRING
                        using (var bitStringStream = new MemoryStream())
                        {
                            var bitStringWriter = new BinaryWriter(bitStringStream);
                            bitStringWriter.Write((byte)0x00); // # of unused bits
                            bitStringWriter.Write((byte)0x30); // SEQUENCE
                            using (var paramsStream = new MemoryStream())
                            {
                                var paramsWriter = new BinaryWriter(paramsStream);
                                EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                                EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                                var paramsLength = (int)paramsStream.Length;
                                EncodeLength(bitStringWriter, paramsLength);
                                if (paramsStream.TryGetBuffer(out ArraySegment<byte> innerBuffer))
                                    bitStringWriter.Write(innerBuffer.ToArray(), 0, paramsLength);
                            }
                            var bitStringLength = (int)bitStringStream.Length;
                            EncodeLength(innerWriter, bitStringLength);
                            if (bitStringStream.TryGetBuffer(out ArraySegment<byte> bitStringBuffer))
                                innerWriter.Write(bitStringBuffer.ToArray(), 0, bitStringLength);
                        }
                        var length = (int)innerStream.Length;
                        EncodeLength(writer, length);
                        if (innerStream.TryGetBuffer(out ArraySegment<byte> innerStreamBuffer))
                            writer.Write(innerStreamBuffer.ToArray(), 0, length);
                    }
                    char[] base64 = { };
                    if (stream.TryGetBuffer(out ArraySegment<byte> outerBuffer))
                        base64 = Convert.ToBase64String(outerBuffer.ToArray(), 0, (int)stream.Length).ToCharArray();
                    outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                    for (var i = 0; i < base64.Length; i += 64)
                    {
                        outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                    }
                    outputStream.WriteLine("-----END PUBLIC KEY-----");
                    var toReturn = outputStream.ToString();
                    outputStream.Dispose();
                    return toReturn;
                }
            }

            public static String ExportPublicKeyToPEMFormat(RSACryptoServiceProvider csp)
            {
                TextWriter outputStream = new StringWriter();

                var parameters = csp.ExportParameters(false);
                using (var stream = new MemoryStream())
                {
                    var writer = new BinaryWriter(stream);
                    writer.Write((byte)0x30); // SEQUENCE
                    using (var innerStream = new MemoryStream())
                    {
                        var innerWriter = new BinaryWriter(innerStream);
                        EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                        EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                        EncodeIntegerBigEndian(innerWriter, parameters.Exponent);

                        //All Parameter Must Have Value so Set Other Parameter Value Whit Invalid Data  (for keeping Key Structure  use "parameters.Exponent" value for invalid data)
                        /*EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.D
                        EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.P
                        EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.Q
                        EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.DP
                        EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.DQ
                        EncodeIntegerBigEndian(innerWriter, parameters.Exponent); // instead of parameters.InverseQ*/

                        var length = (int)innerStream.Length;
                        EncodeLength(writer, length);
                        if (innerStream.TryGetBuffer(out ArraySegment<byte> innerBuffer))
                            writer.Write(innerBuffer.ToArray(), 0, length);
                    }

                    char[] base64 = { };
                    if (stream.TryGetBuffer(out ArraySegment<byte> outerBuffer))
                        base64 = Convert.ToBase64String(outerBuffer.ToArray(), 0, (int)stream.Length).ToCharArray();

                    outputStream.WriteLine("-----BEGIN PUBLIC KEY-----");
                    // Output as Base64 with lines chopped at 64 characters
                    for (var i = 0; i < base64.Length; i += 64)
                    {
                        outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
                    }
                    outputStream.WriteLine("-----END PUBLIC KEY-----");

                    return outputStream.ToString();

                }
            }

            private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
            {
                stream.Write((byte)0x02); // INTEGER
                var prefixZeros = 0;
                for (var i = 0; i < value.Length; i++)
                {
                    if (value[i] != 0) break;
                    prefixZeros++;
                }
                if (value.Length - prefixZeros == 0)
                {
                    EncodeLength(stream, 1);
                    stream.Write((byte)0);
                }
                else
                {
                    if (forceUnsigned && value[prefixZeros] > 0x7f)
                    {
                        // Add a prefix zero to force unsigned if the MSB is 1
                        EncodeLength(stream, value.Length - prefixZeros + 1);
                        stream.Write((byte)0);
                    }
                    else
                    {
                        EncodeLength(stream, value.Length - prefixZeros);
                    }
                    for (var i = prefixZeros; i < value.Length; i++)
                    {
                        stream.Write(value[i]);
                    }
                }
            }

            private static void EncodeLength(BinaryWriter stream, int length)
            {
                if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
                if (length < 0x80)
                {
                    // Short form
                    stream.Write((byte)length);
                }
                else
                {
                    // Long form
                    var temp = length;
                    var bytesRequired = 0;
                    while (temp > 0)
                    {
                        temp >>= 8;
                        bytesRequired++;
                    }
                    stream.Write((byte)(bytesRequired | 0x80));
                    for (var i = bytesRequired - 1; i >= 0; i--)
                    {
                        stream.Write((byte)(length >> (8 * i) & 0xff));
                    }
                }
            }


            public static void FromXmlString(this RSA rsa, string xmlString)
            {
                var parameters = new RSAParameters();
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(xmlString);

                if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
                {
                    foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                    {
                        switch (node.Name)
                        {
                            case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                            case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                            case "P": parameters.P = Convert.FromBase64String(node.InnerText); break;
                            case "Q": parameters.Q = Convert.FromBase64String(node.InnerText); break;
                            case "DP": parameters.DP = Convert.FromBase64String(node.InnerText); break;
                            case "DQ": parameters.DQ = Convert.FromBase64String(node.InnerText); break;
                            case "InverseQ": parameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
                            case "D": parameters.D = Convert.FromBase64String(node.InnerText); break;
                        }
                    }
                }
                else
                {
                    throw new Exception("Invalid XML RSA key.");
                }

                rsa.ImportParameters(parameters);
            }

            public static string PrivateToXmlString(this RSA rsa)
            {
                RSAParameters parameters = rsa.ExportParameters(true);
                return $"<RSAKeyValue><Modulus>{Convert.ToBase64String(parameters.Modulus)}</Modulus><Exponent>{Convert.ToBase64String(parameters.Exponent)}</Exponent><P>{Convert.ToBase64String(parameters.P)}</P><Q>{Convert.ToBase64String(parameters.Q)}</Q><DP>{Convert.ToBase64String(parameters.DP)}</DP><DQ>{Convert.ToBase64String(parameters.DQ)}</DQ><InverseQ>{Convert.ToBase64String(parameters.InverseQ)}</InverseQ><D>{Convert.ToBase64String(parameters.D)}</D></RSAKeyValue>";
            }

            public static string PublicKeyToXmlString(this RSA rsa)
            {
                RSAParameters parameters = rsa.ExportParameters(true);
                return $"<RSAKeyValue><Modulus>{Convert.ToBase64String(parameters.Modulus)}</Modulus><Exponent>{Convert.ToBase64String(parameters.Exponent)}</Exponent></RSAKeyValue>";
            }

            public static void PublicKeyFromXmlString(this RSA rsa, string xmlString)
            {
                var parameters = new RSAParameters();
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(xmlString);

                if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
                {
                    foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                    {
                        switch (node.Name)
                        {
                            case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                            case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                        }
                    }
                }
                else
                {
                    throw new Exception("Invalid XML RSA key.");
                }

                rsa.ImportParameters(parameters);
            }

    }
}
