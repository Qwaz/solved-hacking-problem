package android.support.v4.p006c.p007a;

import android.graphics.drawable.Drawable;

/* renamed from: android.support.v4.c.a.m */
class C0079m {
    public static void m546a(Drawable drawable) {
        drawable.jumpToCurrentState();
    }

    public static Drawable m547b(Drawable drawable) {
        return !(drawable instanceof C0065w) ? new C0065w(drawable) : drawable;
    }
}
