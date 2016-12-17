package android.support.v4.p011f;

import android.util.Log;
import java.lang.reflect.Method;
import java.util.Locale;

/* renamed from: android.support.v4.f.g */
class C0100g {
    private static Method f360a;
    private static Method f361b;

    static {
        try {
            Class cls = Class.forName("libcore.icu.ICU");
            if (cls != null) {
                f360a = cls.getMethod("getScript", new Class[]{String.class});
                f361b = cls.getMethod("addLikelySubtags", new Class[]{String.class});
            }
        } catch (Throwable e) {
            f360a = null;
            f361b = null;
            Log.w("ICUCompatIcs", e);
        }
    }

    private static String m580a(String str) {
        try {
            if (f360a != null) {
                return (String) f360a.invoke(null, new Object[]{str});
            }
        } catch (Throwable e) {
            Log.w("ICUCompatIcs", e);
        } catch (Throwable e2) {
            Log.w("ICUCompatIcs", e2);
        }
        return null;
    }

    public static String m581a(Locale locale) {
        String b = C0100g.m582b(locale);
        return b != null ? C0100g.m580a(b) : null;
    }

    private static String m582b(Locale locale) {
        String locale2 = locale.toString();
        try {
            if (f361b != null) {
                return (String) f361b.invoke(null, new Object[]{locale2});
            }
        } catch (Throwable e) {
            Log.w("ICUCompatIcs", e);
        } catch (Throwable e2) {
            Log.w("ICUCompatIcs", e2);
        }
        return locale2;
    }
}
