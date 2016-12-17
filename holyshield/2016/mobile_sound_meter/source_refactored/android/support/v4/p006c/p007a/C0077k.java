package android.support.v4.p006c.p007a;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import org.xmlpull.v1.XmlPullParser;

/* renamed from: android.support.v4.c.a.k */
class C0077k {
    public static Drawable m540a(Drawable drawable) {
        return !(drawable instanceof C0064r) ? new C0064r(drawable) : drawable;
    }

    public static void m541a(Drawable drawable, int i) {
        if (drawable instanceof C0063q) {
            ((C0063q) drawable).m470a(i);
        }
    }

    public static void m542a(Drawable drawable, ColorStateList colorStateList) {
        if (drawable instanceof C0063q) {
            ((C0063q) drawable).m471a(colorStateList);
        }
    }

    public static void m543a(Drawable drawable, Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        drawable.inflate(resources, xmlPullParser, attributeSet);
    }

    public static void m544a(Drawable drawable, Mode mode) {
        if (drawable instanceof C0063q) {
            ((C0063q) drawable).m472a(mode);
        }
    }
}
