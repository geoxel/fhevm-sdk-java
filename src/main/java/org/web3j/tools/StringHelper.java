package org.web3j.tools;

public final class StringHelper {
    public static boolean startsWithIgnoreCase(String str, String prefix) {
        if (str == null || prefix == null) {
            return false;
        }
        if (prefix.length() > str.length()) {
            return false;
        }
        return str.regionMatches(true/* ignoreCase */, 0, prefix, 0, prefix.length());
    }

    public static boolean endsWithIgnoreCase(String str, String suffix) {
        if (str == null || suffix == null) {
            return false;
        }
        int offset = str.length() - suffix.length();
        if (offset < 0) {
            return false;
        }
        return str.regionMatches(true/* ignoreCase */, offset, suffix, 0, suffix.length());
    }
}
