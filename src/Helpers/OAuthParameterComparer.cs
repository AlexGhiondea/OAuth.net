using System;
using System.Collections.Generic;

namespace OAuth
{
    internal class OAuthParameterComparer : IComparer<KeyValuePair<string, string>>
    {
        public int Compare(KeyValuePair<string, string> param1, KeyValuePair<string, string> param2)
        {
            if (param1.Key == param2.Key)
            {
                return string.Compare(param1.Value, param2.Value, StringComparison.Ordinal);
            }
            else
            {
                return string.Compare(param1.Key, param2.Key, StringComparison.Ordinal);
            }
        }
    }
}
