package android.support.v4.p011f;

import android.os.Build.VERSION;
import java.util.Locale;

/* renamed from: android.support.v4.f.a */
public final class C0094a {
    private static final C0095b f358a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 21) {
            f358a = new C0098e();
        } else if (i >= 14) {
            f358a = new C0097d();
        } else {
            f358a = new C0096c();
        }
    }

    public static String m574a(Locale locale) {
        return f358a.m575a(locale);
    }
}
