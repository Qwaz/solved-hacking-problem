package android.support.v4.p011f;

import android.util.Log;
import java.lang.reflect.Method;
import java.util.Locale;

/* renamed from: android.support.v4.f.f */
class C0099f {
    private static Method f359a;

    static {
        try {
            f359a = Class.forName("libcore.icu.ICU").getMethod("addLikelySubtags", new Class[]{Locale.class});
        } catch (Throwable e) {
            throw new IllegalStateException(e);
        }
    }

    public static String m579a(Locale locale) {
        try {
            return ((Locale) f359a.invoke(null, new Object[]{locale})).getScript();
        } catch (Throwable e) {
            Log.w("ICUCompatIcs", e);
            return locale.getScript();
        } catch (Throwable e2) {
            Log.w("ICUCompatIcs", e2);
            return locale.getScript();
        }
    }
}
