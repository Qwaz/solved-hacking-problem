package org.apache.commons.codec.language.bm;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;
import org.apache.commons.codec.language.bm.Languages.LanguageSet;

public class Rule {
    public static final String ALL = "ALL";
    public static final RPattern ALL_STRINGS_RMATCHER = new C00171();
    private static final String DOUBLE_QUOTE = "\"";
    private static final String HASH_INCLUDE = "#include";
    private static final Map<NameType, Map<RuleType, Map<String, Map<String, List<Rule>>>>> RULES = new EnumMap(NameType.class);
    private final RPattern lContext;
    private final String pattern;
    private final PhonemeExpr phoneme;
    private final RPattern rContext;

    public interface PhonemeExpr {
        Iterable<Phoneme> getPhonemes();
    }

    public interface RPattern {
        boolean isMatch(CharSequence charSequence);
    }

    static class C00171 implements RPattern {
        C00171() {
        }

        public boolean isMatch(CharSequence input) {
            return true;
        }
    }

    static class C00193 implements RPattern {
        C00193() {
        }

        public boolean isMatch(CharSequence input) {
            return input.length() == 0;
        }
    }

    public static final class Phoneme implements PhonemeExpr {
        public static final Comparator<Phoneme> COMPARATOR = new C00141();
        private final LanguageSet languages;
        private final StringBuilder phonemeText;

        static class C00141 implements Comparator<Phoneme> {
            C00141() {
            }

            public int compare(Phoneme o1, Phoneme o2) {
                for (int i = 0; i < o1.phonemeText.length(); i++) {
                    if (i >= o2.phonemeText.length()) {
                        return 1;
                    }
                    int c = o1.phonemeText.charAt(i) - o2.phonemeText.charAt(i);
                    if (c != 0) {
                        return c;
                    }
                }
                if (o1.phonemeText.length() < o2.phonemeText.length()) {
                    return -1;
                }
                return 0;
            }
        }

        public Phoneme(CharSequence phonemeText, LanguageSet languages) {
            this.phonemeText = new StringBuilder(phonemeText);
            this.languages = languages;
        }

        public Phoneme(Phoneme phonemeLeft, Phoneme phonemeRight) {
            this(phonemeLeft.phonemeText, phonemeLeft.languages);
            this.phonemeText.append(phonemeRight.phonemeText);
        }

        public Phoneme(Phoneme phonemeLeft, Phoneme phonemeRight, LanguageSet languages) {
            this(phonemeLeft.phonemeText, languages);
            this.phonemeText.append(phonemeRight.phonemeText);
        }

        public Phoneme append(CharSequence str) {
            this.phonemeText.append(str);
            return this;
        }

        public LanguageSet getLanguages() {
            return this.languages;
        }

        public Iterable<Phoneme> getPhonemes() {
            return Collections.singleton(this);
        }

        public CharSequence getPhonemeText() {
            return this.phonemeText;
        }

        @Deprecated
        public Phoneme join(Phoneme right) {
            return new Phoneme(this.phonemeText.toString() + right.phonemeText.toString(), this.languages.restrictTo(right.languages));
        }
    }

    public static final class PhonemeList implements PhonemeExpr {
        private final List<Phoneme> phonemes;

        public PhonemeList(List<Phoneme> phonemes) {
            this.phonemes = phonemes;
        }

        public List<Phoneme> getPhonemes() {
            return this.phonemes;
        }
    }

    static {
        for (NameType s : NameType.values()) {
            Map<RuleType, Map<String, Map<String, List<Rule>>>> rts = new EnumMap(RuleType.class);
            for (RuleType rt : RuleType.values()) {
                Map<String, Map<String, List<Rule>>> rs = new HashMap();
                for (String l : Languages.getInstance(s).getLanguages()) {
                    try {
                        rs.put(l, parseRules(createScanner(s, rt, l), createResourceName(s, rt, l)));
                    } catch (IllegalStateException e) {
                        throw new IllegalStateException("Problem processing " + createResourceName(s, rt, l), e);
                    }
                }
                if (!rt.equals(RuleType.RULES)) {
                    rs.put("common", parseRules(createScanner(s, rt, "common"), createResourceName(s, rt, "common")));
                }
                rts.put(rt, Collections.unmodifiableMap(rs));
            }
            RULES.put(s, Collections.unmodifiableMap(rts));
        }
    }

    private static boolean contains(CharSequence chars, char input) {
        for (int i = 0; i < chars.length(); i++) {
            if (chars.charAt(i) == input) {
                return true;
            }
        }
        return false;
    }

    private static String createResourceName(NameType nameType, RuleType rt, String lang) {
        return String.format("org/apache/commons/codec/language/bm/%s_%s_%s.txt", new Object[]{nameType.getName(), rt.getName(), lang});
    }

    private static Scanner createScanner(NameType nameType, RuleType rt, String lang) {
        String resName = createResourceName(nameType, rt, lang);
        InputStream rulesIS = Languages.class.getClassLoader().getResourceAsStream(resName);
        if (rulesIS != null) {
            return new Scanner(rulesIS, "UTF-8");
        }
        throw new IllegalArgumentException("Unable to load resource: " + resName);
    }

    private static Scanner createScanner(String lang) {
        String resName = String.format("org/apache/commons/codec/language/bm/%s.txt", new Object[]{lang});
        InputStream rulesIS = Languages.class.getClassLoader().getResourceAsStream(resName);
        if (rulesIS != null) {
            return new Scanner(rulesIS, "UTF-8");
        }
        throw new IllegalArgumentException("Unable to load resource: " + resName);
    }

    private static boolean endsWith(CharSequence input, CharSequence suffix) {
        if (suffix.length() > input.length()) {
            return false;
        }
        int i = input.length() - 1;
        for (int j = suffix.length() - 1; j >= 0; j--) {
            if (input.charAt(i) != suffix.charAt(j)) {
                return false;
            }
            i--;
        }
        return true;
    }

    public static List<Rule> getInstance(NameType nameType, RuleType rt, LanguageSet langs) {
        Map<String, List<Rule>> ruleMap = getInstanceMap(nameType, rt, langs);
        List<Rule> allRules = new ArrayList();
        for (List<Rule> rules : ruleMap.values()) {
            allRules.addAll(rules);
        }
        return allRules;
    }

    public static List<Rule> getInstance(NameType nameType, RuleType rt, String lang) {
        return getInstance(nameType, rt, LanguageSet.from(new HashSet(Arrays.asList(new String[]{lang}))));
    }

    public static Map<String, List<Rule>> getInstanceMap(NameType nameType, RuleType rt, LanguageSet langs) {
        return langs.isSingleton() ? getInstanceMap(nameType, rt, langs.getAny()) : getInstanceMap(nameType, rt, Languages.ANY);
    }

    public static Map<String, List<Rule>> getInstanceMap(NameType nameType, RuleType rt, String lang) {
        Map<String, List<Rule>> rules = (Map) ((Map) ((Map) RULES.get(nameType)).get(rt)).get(lang);
        if (rules != null) {
            return rules;
        }
        throw new IllegalArgumentException(String.format("No rules found for %s, %s, %s.", new Object[]{nameType.getName(), rt.getName(), lang}));
    }

    private static Phoneme parsePhoneme(String ph) {
        int open = ph.indexOf("[");
        if (open < 0) {
            return new Phoneme((CharSequence) ph, Languages.ANY_LANGUAGE);
        }
        if (ph.endsWith("]")) {
            return new Phoneme(ph.substring(0, open), LanguageSet.from(new HashSet(Arrays.asList(ph.substring(open + 1, ph.length() - 1).split("[+]")))));
        }
        throw new IllegalArgumentException("Phoneme expression contains a '[' but does not end in ']'");
    }

    private static PhonemeExpr parsePhonemeExpr(String ph) {
        if (!ph.startsWith("(")) {
            return parsePhoneme(ph);
        }
        if (ph.endsWith(")")) {
            List<Phoneme> phs = new ArrayList();
            String body = ph.substring(1, ph.length() - 1);
            for (String part : body.split("[|]")) {
                phs.add(parsePhoneme(part));
            }
            if (body.startsWith("|") || body.endsWith("|")) {
                phs.add(new Phoneme((CharSequence) "", Languages.ANY_LANGUAGE));
            }
            return new PhonemeList(phs);
        }
        throw new IllegalArgumentException("Phoneme starts with '(' so must end with ')'");
    }

    private static Map<String, List<Rule>> parseRules(Scanner scanner, String location) {
        Map<String, List<Rule>> lines = new HashMap();
        int currentLine = 0;
        boolean inMultilineComment = false;
        while (scanner.hasNextLine()) {
            currentLine++;
            String rawLine = scanner.nextLine();
            String line = rawLine;
            if (inMultilineComment) {
                if (line.endsWith("*/")) {
                    inMultilineComment = false;
                }
            } else if (line.startsWith("/*")) {
                inMultilineComment = true;
            } else {
                int cmtI = line.indexOf("//");
                if (cmtI >= 0) {
                    line = line.substring(0, cmtI);
                }
                line = line.trim();
                if (line.length() == 0) {
                    continue;
                } else if (line.startsWith(HASH_INCLUDE)) {
                    String incl = line.substring(HASH_INCLUDE.length()).trim();
                    if (incl.contains(" ")) {
                        throw new IllegalArgumentException("Malformed import statement '" + rawLine + "' in " + location);
                    }
                    lines.putAll(parseRules(createScanner(incl), location + "->" + incl));
                } else {
                    String[] parts = line.split("\\s+");
                    if (parts.length != 4) {
                        throw new IllegalArgumentException("Malformed rule statement split into " + parts.length + " parts: " + rawLine + " in " + location);
                    }
                    try {
                        final int cLine = currentLine;
                        final String str = location;
                        Rule r = new Rule(stripQuotes(parts[0]), stripQuotes(parts[1]), stripQuotes(parts[2]), parsePhonemeExpr(stripQuotes(parts[3]))) {
                            private final String loc = str;
                            private final int myLine = cLine;

                            public String toString() {
                                StringBuilder sb = new StringBuilder();
                                sb.append("Rule");
                                sb.append("{line=").append(this.myLine);
                                sb.append(", loc='").append(this.loc).append('\'');
                                sb.append('}');
                                return sb.toString();
                            }
                        };
                        String patternKey = r.pattern.substring(0, 1);
                        List<Rule> rules = (List) lines.get(patternKey);
                        if (rules == null) {
                            rules = new ArrayList();
                            lines.put(patternKey, rules);
                        }
                        rules.add(r);
                    } catch (IllegalArgumentException e) {
                        throw new IllegalStateException("Problem parsing line '" + currentLine + "' in " + location, e);
                    }
                }
            }
        }
        return lines;
    }

    private static RPattern pattern(final String regex) {
        int i;
        int length;
        boolean shouldMatch = true;
        boolean startsWith = regex.startsWith("^");
        boolean endsWith = regex.endsWith("$");
        if (startsWith) {
            i = 1;
        } else {
            i = 0;
        }
        if (endsWith) {
            length = regex.length() - 1;
        } else {
            length = regex.length();
        }
        final String content = regex.substring(i, length);
        if (content.contains("[")) {
            boolean startsWithBox = content.startsWith("[");
            boolean endsWithBox = content.endsWith("]");
            if (startsWithBox && endsWithBox) {
                String boxContent = content.substring(1, content.length() - 1);
                if (!boxContent.contains("[")) {
                    boolean negate = boxContent.startsWith("^");
                    if (negate) {
                        boxContent = boxContent.substring(1);
                    }
                    final String bContent = boxContent;
                    if (negate) {
                        shouldMatch = false;
                    }
                    if (startsWith && endsWith) {
                        return new RPattern() {
                            public boolean isMatch(CharSequence input) {
                                return input.length() == 1 && Rule.contains(bContent, input.charAt(0)) == shouldMatch;
                            }
                        };
                    }
                    if (startsWith) {
                        return new RPattern() {
                            public boolean isMatch(CharSequence input) {
                                return input.length() > 0 && Rule.contains(bContent, input.charAt(0)) == shouldMatch;
                            }
                        };
                    }
                    if (endsWith) {
                        return new RPattern() {
                            public boolean isMatch(CharSequence input) {
                                return input.length() > 0 && Rule.contains(bContent, input.charAt(input.length() - 1)) == shouldMatch;
                            }
                        };
                    }
                }
            }
        } else if (startsWith && endsWith) {
            if (content.length() == 0) {
                return new C00193();
            }
            return new RPattern() {
                public boolean isMatch(CharSequence input) {
                    return input.equals(content);
                }
            };
        } else if ((startsWith || endsWith) && content.length() == 0) {
            return ALL_STRINGS_RMATCHER;
        } else {
            if (startsWith) {
                return new RPattern() {
                    public boolean isMatch(CharSequence input) {
                        return Rule.startsWith(input, content);
                    }
                };
            }
            if (endsWith) {
                return new RPattern() {
                    public boolean isMatch(CharSequence input) {
                        return Rule.endsWith(input, content);
                    }
                };
            }
        }
        return new RPattern() {
            Pattern pattern = Pattern.compile(regex);

            public boolean isMatch(CharSequence input) {
                return this.pattern.matcher(input).find();
            }
        };
    }

    private static boolean startsWith(CharSequence input, CharSequence prefix) {
        if (prefix.length() > input.length()) {
            return false;
        }
        for (int i = 0; i < prefix.length(); i++) {
            if (input.charAt(i) != prefix.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    private static String stripQuotes(String str) {
        if (str.startsWith(DOUBLE_QUOTE)) {
            str = str.substring(1);
        }
        if (str.endsWith(DOUBLE_QUOTE)) {
            return str.substring(0, str.length() - 1);
        }
        return str;
    }

    public Rule(String pattern, String lContext, String rContext, PhonemeExpr phoneme) {
        this.pattern = pattern;
        this.lContext = pattern(lContext + "$");
        this.rContext = pattern("^" + rContext);
        this.phoneme = phoneme;
    }

    public RPattern getLContext() {
        return this.lContext;
    }

    public String getPattern() {
        return this.pattern;
    }

    public PhonemeExpr getPhoneme() {
        return this.phoneme;
    }

    public RPattern getRContext() {
        return this.rContext;
    }

    public boolean patternAndContextMatches(CharSequence input, int i) {
        if (i < 0) {
            throw new IndexOutOfBoundsException("Can not match pattern at negative indexes");
        }
        int ipl = i + this.pattern.length();
        if (ipl <= input.length() && input.subSequence(i, ipl).equals(this.pattern) && this.rContext.isMatch(input.subSequence(ipl, input.length()))) {
            return this.lContext.isMatch(input.subSequence(0, i));
        }
        return false;
    }
}
