using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Tps.Crm.Assertion
{
    internal static class Base64Url
    {
        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>Strict decode: no padding, no foreign characters, canonical only. Returns null on failure.</summary>
        public static byte[] Decode(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length % 4 == 1) return null;
            foreach (char c in s)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
                if (!ok) return null;
            }
            string b64 = s.Replace('-', '+').Replace('_', '/');
            b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
            try
            {
                byte[] bytes = Convert.FromBase64String(b64);
                return Encode(bytes) == s ? bytes : null;
            }
            catch (FormatException)
            {
                return null;
            }
        }
    }

    internal static class CertThumbprint
    {
        /// <summary>Lower-case hex SHA-256 of the DER certificate.</summary>
        public static string Sha256(X509Certificate2 cert)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(cert.RawData);
                StringBuilder sb = new StringBuilder(h.Length * 2);
                foreach (byte b in h) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }
    }

    /// <summary>Minimal strict JSON for flat objects of string / integer values. Duplicate keys are rejected.</summary>
    internal static class FlatJson
    {
        public static string Write(IList<KeyValuePair<string, object>> items)
        {
            StringBuilder sb = new StringBuilder("{");
            for (int i = 0; i < items.Count; i++)
            {
                if (i > 0) sb.Append(',');
                WriteString(sb, items[i].Key);
                sb.Append(':');
                object v = items[i].Value;
                if (v is string) WriteString(sb, (string)v);
                else sb.Append(Convert.ToInt64(v, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture));
            }
            return sb.Append('}').ToString();
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                if (c == '"') sb.Append("\\\"");
                else if (c == '\\') sb.Append("\\\\");
                else if (c < 0x20 || c > 0x7e) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                else sb.Append(c);
            }
            sb.Append('"');
        }

        /// <summary>Returns null when the text is not a flat object of strings/integers.</summary>
        public static Dictionary<string, object> Parse(string json)
        {
            if (json == null) return null;
            int p = 0;
            var result = new Dictionary<string, object>(StringComparer.Ordinal);
            SkipWs(json, ref p);
            if (!Take(json, ref p, '{')) return null;
            SkipWs(json, ref p);
            if (Peek(json, p) == '}') { p++; return AtEnd(json, p) ? result : null; }
            while (true)
            {
                SkipWs(json, ref p);
                string key = ReadString(json, ref p);
                if (key == null) return null;
                SkipWs(json, ref p);
                if (!Take(json, ref p, ':')) return null;
                SkipWs(json, ref p);
                object value;
                char c = Peek(json, p);
                if (c == '"')
                {
                    value = ReadString(json, ref p);
                    if (value == null) return null;
                }
                else if (c == '-' || (c >= '0' && c <= '9'))
                {
                    int start = p;
                    if (c == '-') p++;
                    int digits = p;
                    while (p < json.Length && json[p] >= '0' && json[p] <= '9') p++;
                    int n = p - digits;
                    if (n == 0 || n > 15 || (n > 1 && json[digits] == '0')) return null;
                    char after = Peek(json, p);
                    if (after == '.' || after == 'e' || after == 'E') return null;
                    value = long.Parse(json.Substring(start, p - start), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
                }
                else return null;
                if (result.ContainsKey(key)) return null;
                result.Add(key, value);
                SkipWs(json, ref p);
                char d = Peek(json, p);
                if (d == ',') { p++; continue; }
                if (d == '}') { p++; break; }
                return null;
            }
            return AtEnd(json, p) ? result : null;
        }

        private static char Peek(string s, int p) { return p < s.Length ? s[p] : '\0'; }
        private static bool Take(string s, ref int p, char c) { if (Peek(s, p) != c) return false; p++; return true; }
        private static void SkipWs(string s, ref int p) { while (p < s.Length && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n')) p++; }
        private static bool AtEnd(string s, int p) { SkipWs(s, ref p); return p == s.Length; }

        private static string ReadString(string s, ref int p)
        {
            if (!Take(s, ref p, '"')) return null;
            StringBuilder sb = new StringBuilder();
            while (p < s.Length)
            {
                char c = s[p++];
                if (c == '"') return sb.ToString();
                if (c < 0x20) return null;
                if (c != '\\') { sb.Append(c); continue; }
                if (p >= s.Length) return null;
                char e = s[p++];
                switch (e)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        int code;
                        if (p + 4 > s.Length || !int.TryParse(s.Substring(p, 4), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out code)) return null;
                        sb.Append((char)code);
                        p += 4;
                        break;
                    default: return null;
                }
            }
            return null;
        }
    }
}
