package android.support.v4.p011f;

import android.os.Build.VERSION;
import java.util.Locale;

/* renamed from: android.support.v4.f.h */
public final class C0101h {
    public static final Locale f362a;
    private static final C0103j f363b;
    private static String f364c;
    private static String f365d;

    static {
        if (VERSION.SDK_INT >= 17) {
            f363b = new C0104k();
        } else {
            f363b = new C0103j();
        }
        f362a = new Locale("", "");
        f364c = "Arab";
        f365d = "Hebr";
    }

    public static int m583a(Locale locale) {
        return f363b.m587a(locale);
    }
}
