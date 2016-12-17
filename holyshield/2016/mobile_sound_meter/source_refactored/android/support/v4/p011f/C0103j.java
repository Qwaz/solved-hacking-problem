package android.support.v4.p011f;

import android.support.v7.p015b.C0243l;
import java.util.Locale;

/* renamed from: android.support.v4.f.j */
class C0103j {
    private C0103j() {
    }

    private static int m586b(Locale locale) {
        switch (Character.getDirectionality(locale.getDisplayName(locale).charAt(0))) {
            case C0243l.View_android_focusable /*1*/:
            case C0243l.View_paddingStart /*2*/:
                return 1;
            default:
                return 0;
        }
    }

    public int m587a(Locale locale) {
        if (!(locale == null || locale.equals(C0101h.f362a))) {
            String a = C0094a.m574a(locale);
            if (a == null) {
                return C0103j.m586b(locale);
            }
            if (a.equalsIgnoreCase(C0101h.f364c) || a.equalsIgnoreCase(C0101h.f365d)) {
                return 1;
            }
        }
        return 0;
    }
}
