package android.support.v4.p006c.p007a;

import android.graphics.drawable.Drawable;

/* renamed from: android.support.v4.c.a.o */
class C0081o {
    public static void m549a(Drawable drawable, boolean z) {
        drawable.setAutoMirrored(z);
    }

    public static boolean m550a(Drawable drawable) {
        return drawable.isAutoMirrored();
    }

    public static Drawable m551b(Drawable drawable) {
        return !(drawable instanceof C0066y) ? new C0066y(drawable) : drawable;
    }

    public static int m552c(Drawable drawable) {
        return drawable.getAlpha();
    }
}
