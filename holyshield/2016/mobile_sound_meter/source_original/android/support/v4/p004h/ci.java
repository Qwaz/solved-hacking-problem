package android.support.v4.p004h;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.view.View;
import java.lang.reflect.Field;

/* renamed from: android.support.v4.h.ci */
class ci {
    private static Field f448a;
    private static boolean f449b;

    static ColorStateList m1134a(View view) {
        return view instanceof bo ? ((bo) view).getSupportBackgroundTintList() : null;
    }

    static void m1135a(View view, ColorStateList colorStateList) {
        if (view instanceof bo) {
            ((bo) view).setSupportBackgroundTintList(colorStateList);
        }
    }

    static void m1136a(View view, Mode mode) {
        if (view instanceof bo) {
            ((bo) view).setSupportBackgroundTintMode(mode);
        }
    }

    static Mode m1137b(View view) {
        return view instanceof bo ? ((bo) view).getSupportBackgroundTintMode() : null;
    }

    static boolean m1138c(View view) {
        return view.getWidth() > 0 && view.getHeight() > 0;
    }

    static int m1139d(View view) {
        if (!f449b) {
            try {
                f448a = View.class.getDeclaredField("mMinHeight");
                f448a.setAccessible(true);
            } catch (NoSuchFieldException e) {
            }
            f449b = true;
        }
        if (f448a != null) {
            try {
                return ((Integer) f448a.get(view)).intValue();
            } catch (Exception e2) {
            }
        }
        return 0;
    }

    static boolean m1140e(View view) {
        return view.getWindowToken() != null;
    }
}
