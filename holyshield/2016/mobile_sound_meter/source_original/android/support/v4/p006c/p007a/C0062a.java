package android.support.v4.p006c.p007a;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.util.AttributeSet;
import org.xmlpull.v1.XmlPullParser;

/* renamed from: android.support.v4.c.a.a */
public final class C0062a {
    static final C0068c f343a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 23) {
            f343a = new C0075i();
        } else if (i >= 21) {
            f343a = new C0074h();
        } else if (i >= 19) {
            f343a = new C0073g();
        } else if (i >= 17) {
            f343a = new C0072f();
        } else if (i >= 11) {
            f343a = new C0071e();
        } else if (i >= 5) {
            f343a = new C0070d();
        } else {
            f343a = new C0069b();
        }
    }

    public static void m454a(Drawable drawable) {
        f343a.m489a(drawable);
    }

    public static void m455a(Drawable drawable, float f, float f2) {
        f343a.m490a(drawable, f, f2);
    }

    public static void m456a(Drawable drawable, int i) {
        f343a.m491a(drawable, i);
    }

    public static void m457a(Drawable drawable, int i, int i2, int i3, int i4) {
        f343a.m492a(drawable, i, i2, i3, i4);
    }

    public static void m458a(Drawable drawable, ColorStateList colorStateList) {
        f343a.m493a(drawable, colorStateList);
    }

    public static void m459a(Drawable drawable, Theme theme) {
        f343a.m494a(drawable, theme);
    }

    public static void m460a(Drawable drawable, Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        f343a.m495a(drawable, resources, xmlPullParser, attributeSet, theme);
    }

    public static void m461a(Drawable drawable, Mode mode) {
        f343a.m496a(drawable, mode);
    }

    public static void m462a(Drawable drawable, boolean z) {
        f343a.m497a(drawable, z);
    }

    public static boolean m463b(Drawable drawable) {
        return f343a.m498b(drawable);
    }

    public static int m464c(Drawable drawable) {
        return f343a.m501e(drawable);
    }

    public static boolean m465d(Drawable drawable) {
        return f343a.m502f(drawable);
    }

    public static ColorFilter m466e(Drawable drawable) {
        return f343a.m503g(drawable);
    }

    public static Drawable m467f(Drawable drawable) {
        return f343a.m499c(drawable);
    }

    public static int m468g(Drawable drawable) {
        return f343a.m500d(drawable);
    }
}
