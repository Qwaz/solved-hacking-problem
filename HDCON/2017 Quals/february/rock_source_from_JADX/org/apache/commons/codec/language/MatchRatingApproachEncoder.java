package org.apache.commons.codec.language;

import java.util.Locale;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;

public class MatchRatingApproachEncoder implements StringEncoder {
    private static final String[] DOUBLE_CONSONANT = new String[]{"BB", "CC", "DD", "FF", "GG", "HH", "JJ", "KK", "LL", "MM", "NN", "PP", "QQ", "RR", "SS", "TT", "VV", "WW", "XX", "YY", "ZZ"};
    private static final int EIGHT = 8;
    private static final int ELEVEN = 11;
    private static final String EMPTY = "";
    private static final int FIVE = 5;
    private static final int FOUR = 4;
    private static final int ONE = 1;
    private static final String PLAIN_ASCII = "AaEeIiOoUuAaEeIiOoUuYyAaEeIiOoUuYyAaOoNnAaEeIiOoUuYyAaCcOoUu";
    private static final int SEVEN = 7;
    private static final int SIX = 6;
    private static final String SPACE = " ";
    private static final int THREE = 3;
    private static final int TWELVE = 12;
    private static final int TWO = 2;
    private static final String UNICODE = "ÀàÈèÌìÒòÙùÁáÉéÍíÓóÚúÝýÂâÊêÎîÔôÛûŶŷÃãÕõÑñÄäËëÏïÖöÜüŸÿÅåÇçŐőŰű";

    String cleanName(String name) {
        String upperName = name.toUpperCase(Locale.ENGLISH);
        for (String str : new String[]{"\\-", "[&]", "\\'", "\\.", "[\\,]"}) {
            upperName = upperName.replaceAll(str, "");
        }
        return removeAccents(upperName).replaceAll("\\s+", "");
    }

    public final Object encode(Object pObject) throws EncoderException {
        if (pObject instanceof String) {
            return encode((String) pObject);
        }
        throw new EncoderException("Parameter supplied to Match Rating Approach encoder is not of type java.lang.String");
    }

    public final String encode(String name) {
        if (name == null || "".equalsIgnoreCase(name) || SPACE.equalsIgnoreCase(name) || name.length() == 1) {
            return "";
        }
        return getFirst3Last3(removeDoubleConsonants(removeVowels(cleanName(name))));
    }

    String getFirst3Last3(String name) {
        int nameLength = name.length();
        if (nameLength <= 6) {
            return name;
        }
        String firstThree = name.substring(0, 3);
        return firstThree + name.substring(nameLength - 3, nameLength);
    }

    int getMinRating(int sumLength) {
        if (sumLength <= 4) {
            return 5;
        }
        if (sumLength >= 5 && sumLength <= 7) {
            return 4;
        }
        if (sumLength >= 8 && sumLength <= 11) {
            return 3;
        }
        if (sumLength == 12) {
            return 2;
        }
        return 1;
    }

    public boolean isEncodeEquals(String name1, String name2) {
        boolean z = true;
        if (name1 == null || "".equalsIgnoreCase(name1) || SPACE.equalsIgnoreCase(name1) || name2 == null || "".equalsIgnoreCase(name2) || SPACE.equalsIgnoreCase(name2) || name1.length() == 1 || name2.length() == 1) {
            return false;
        }
        if (name1.equalsIgnoreCase(name2)) {
            return true;
        }
        name1 = cleanName(name1);
        name2 = cleanName(name2);
        name1 = removeVowels(name1);
        name2 = removeVowels(name2);
        name1 = removeDoubleConsonants(name1);
        name2 = removeDoubleConsonants(name2);
        name1 = getFirst3Last3(name1);
        name2 = getFirst3Last3(name2);
        if (Math.abs(name1.length() - name2.length()) >= 3) {
            return false;
        }
        if (leftToRightThenRightToLeftProcessing(name1, name2) < getMinRating(Math.abs(name1.length() + name2.length()))) {
            z = false;
        }
        return z;
    }

    boolean isVowel(String letter) {
        return letter.equalsIgnoreCase("E") || letter.equalsIgnoreCase("A") || letter.equalsIgnoreCase("O") || letter.equalsIgnoreCase("I") || letter.equalsIgnoreCase("U");
    }

    int leftToRightThenRightToLeftProcessing(String name1, String name2) {
        char[] name1Char = name1.toCharArray();
        char[] name2Char = name2.toCharArray();
        int name1Size = name1.length() - 1;
        int name2Size = name2.length() - 1;
        String name1LtRStart = "";
        String name1LtREnd = "";
        String name2RtLStart = "";
        String name2RtLEnd = "";
        int i = 0;
        while (i < name1Char.length && i <= name2Size) {
            name1LtRStart = name1.substring(i, i + 1);
            name1LtREnd = name1.substring(name1Size - i, (name1Size - i) + 1);
            name2RtLStart = name2.substring(i, i + 1);
            name2RtLEnd = name2.substring(name2Size - i, (name2Size - i) + 1);
            if (name1LtRStart.equals(name2RtLStart)) {
                name1Char[i] = ' ';
                name2Char[i] = ' ';
            }
            if (name1LtREnd.equals(name2RtLEnd)) {
                name1Char[name1Size - i] = ' ';
                name2Char[name2Size - i] = ' ';
            }
            i++;
        }
        String strA = new String(name1Char).replaceAll("\\s+", "");
        String strB = new String(name2Char).replaceAll("\\s+", "");
        if (strA.length() > strB.length()) {
            return Math.abs(6 - strA.length());
        }
        return Math.abs(6 - strB.length());
    }

    String removeAccents(String accentedWord) {
        if (accentedWord == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        int n = accentedWord.length();
        for (int i = 0; i < n; i++) {
            char c = accentedWord.charAt(i);
            int pos = UNICODE.indexOf(c);
            if (pos > -1) {
                sb.append(PLAIN_ASCII.charAt(pos));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    String removeDoubleConsonants(String name) {
        String replacedName = name.toUpperCase();
        for (String dc : DOUBLE_CONSONANT) {
            if (replacedName.contains(dc)) {
                replacedName = replacedName.replace(dc, dc.substring(0, 1));
            }
        }
        return replacedName;
    }

    String removeVowels(String name) {
        String firstLetter = name.substring(0, 1);
        name = name.replaceAll("A", "").replaceAll("E", "").replaceAll("I", "").replaceAll("O", "").replaceAll("U", "").replaceAll("\\s{2,}\\b", SPACE);
        if (isVowel(firstLetter)) {
            return firstLetter + name;
        }
        return name;
    }
}
