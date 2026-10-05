using System;
// Negative-control oracle for patch-variant task cc3e210b99471a78
// Replicates VERBATIM the stock 10.0.12 logic of
// targets/dotnet-aspnetcore-10.0.12/src/Security/Authentication/Negotiate/src/Internal/LdapAdapter.cs
// (lines 17-18, 94, 177-206) so its parsing/escaping invariants can be probed offline.
// targets/ is never modified or referenced at build time.
using System.Text;
using System.Text.RegularExpressions;

namespace LdapDnOracle;

internal static partial class StockLdapAdapter
{
    // stock line 17-18. Stock 10.0.12 declares this as a [GeneratedRegex] *property*
    // (C# 13 / net9+). The property form is unavailable on the net8 SDK present here, so the
    // identical pattern is declared in the equivalent method form; the regex engine semantics
    // of (?<![^\\]\\), are unchanged between the two declaration forms.
    [GeneratedRegex(@"(?<![^\\]\\),")]
    private static partial Regex DnSepRegex();

    internal static Regex DistinguishedNameSeparatorRegex => DnSepRegex();

    // stock line 94 / 158
    internal static string GroupCnFromDn(string groupDN)
        => DistinguishedNameSeparatorRegex.Split(groupDN)[0].Substring("CN=".Length);

    // stock line 177-206
    internal static string EscapeLdapFilterValue(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append(@"\5c"); break;
                case '*':  sb.Append(@"\2a"); break;
                case '(':  sb.Append(@"\28"); break;
                case ')':  sb.Append(@"\29"); break;
                case '\0': sb.Append(@"\00"); break;
                default:   sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    // stock line 69
    internal static string BuildUserFilter(string userAccountName)
        => $"(&(objectClass=user)(sAMAccountName={EscapeLdapFilterValue(userAccountName)}))";
}

internal static class Program
{
    private static int _fail;

    private static void Dn(string label, string dn, string expectCn)
    {
        string got;
        try { got = StockLdapAdapter.GroupCnFromDn(dn); }
        catch (Exception ex) { got = $"<{ex.GetType().Name}>"; }
        var ok = got == expectCn;
        if (!ok) { _fail++; }
        Console.WriteLine($"{(ok ? "MATCH " : "DIVERGE")} | {label,-46} | dn={Show(dn),-40} | intendedCN={Show(expectCn),-22} | parsedCN={Show(got)}");
    }

    private static void Esc(string label, string value)
    {
        var f = StockLdapAdapter.BuildUserFilter(value);
        var balanced = Balanced(f);
        var conjuncts = CountTopLevelConjuncts(f);
        Console.WriteLine($"{(balanced && conjuncts == 2 ? "SAFE   " : "BROKEN ")} | {label,-46} | in={Show(value),-30} | filter={f}");
    }

    private static bool Balanced(string s)
    {
        int d = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (i > 0 && s[i - 1] == '\\') { continue; }
            if (s[i] == '(') { d++; }
            else if (s[i] == ')') { d--; if (d < 0) { return false; } }
        }
        return d == 0;
    }

    // number of filter components directly inside the top-level (&...)
    private static int CountTopLevelConjuncts(string s)
    {
        int d = 0, n = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (i > 0 && s[i - 1] == '\\') { continue; }
            if (s[i] == '(') { d++; if (d == 2) { n++; } }
            else if (s[i] == ')') { d--; }
        }
        return n;
    }

    private static string Show(string s)
        => s.Replace("\\", "\\\\").Replace("\0", "\\0");

    private static int Main()
    {
        Console.WriteLine("== A. DN -> role-claim CN parsing (stock DistinguishedNameSeparatorRegex) ==");
        Console.WriteLine("   'intendedCN' = the RFC-4514-decoded CN the directory object actually has.\n");

        // Cases covered by the shipped regression tests (expected to MATCH).
        Dn("plain",                       @"CN=Testing group - City,DC=x", "Testing group - City");
        Dn("regtest: escaped comma",      @"CN=Testing group\,City,DC=x",  @"Testing group\,City");
        Dn("regtest: unescaped comma",    @"CN=Testing group,City",        "Testing group");
        Dn("regtest: esc backslash+comma",@"CN=Testing group\\,City",      @"Testing group\\");

        Console.WriteLine();
        // Case NOT covered by any shipped regression test:
        // CN literal = `Admins\,ReadOnly`  (a literal backslash followed by a literal comma)
        // RFC 4514 encodes that as  \\  then  \,   ==>  CN=Admins\\\,ReadOnly
        Dn("UNTESTED: literal backslash + escaped comma", @"CN=Admins\\\,ReadOnly,DC=x", @"Admins\\\,ReadOnly");
        Dn("UNTESTED: 5 backslashes + escaped comma",     @"CN=A\\\\\,B,DC=x",           @"A\\\\\,B");

        Console.WriteLine();
        Console.WriteLine("== B. first-RDN assumptions of Substring(\"CN=\".Length) ==");
        Dn("non-CN leading RDN (OU=)",    @"OU=Groups,DC=x",               "Groups");
        Dn("empty first RDN",             @",CN=x,DC=y",                   "<ArgumentOutOfRangeException>");
        Dn("short first RDN",             @"a=,DC=y",                      "");

        Console.WriteLine();
        Console.WriteLine("== C. CN-only role claim collides across containers ==");
        Dn("privileged group",            @"CN=Admins,OU=Corp,DC=x",       "Admins");
        Dn("attacker-controlled OU",      @"CN=Admins,OU=Guests,DC=x",     "Admins");

        Console.WriteLine();
        Console.WriteLine("== D. filter escaping (stock EscapeLdapFilterValue) ==");
        Esc("plain",                        "alice");
        Esc("classic injection",            "x)(sAMAccountName=*");
        Esc("wildcard",                     "*");
        Esc("extensible-match attempt",     "x:caseExactMatch:=y");
        Esc("GE/LE/APPROX attempt",         "x>=0");
        Esc("embedded NUL",                 "alice\0)(objectClass=*");
        Esc("backslash hex smuggle",        @"\2a");
        Esc("close-all + new clause",       "a))(|(objectClass=*");

        Console.WriteLine();
        Console.WriteLine(_fail == 0
            ? "RESULT: no DN parsing divergence observed"
            : $"RESULT: {_fail} DN parsing divergence(s) observed");
        return 0;
    }
}
