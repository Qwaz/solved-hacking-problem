package android.support.v4.p006c.p007a;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import org.xmlpull.v1.XmlPullParser;

/* renamed from: android.support.v4.c.a.p */
class C0082p {
    public static Drawable m553a(Drawable drawable) {
        return !(drawable instanceof aa) ? new aa(drawable) : drawable;
    }

    public static void m554a(Drawable drawable, float f, float f2) {
        drawable.setHotspot(f, f2);
    }

    public static void m555a(Drawable drawable, int i) {
        drawable.setTint(i);
    }

    public static void m556a(Drawable drawable, int i, int i2, int i3, int i4) {
        drawable.setHotspotBounds(i, i2, i3, i4);
    }

    public static void m557a(Drawable drawable, ColorStateList colorStateList) {
        drawable.setTintList(colorStateList);
    }

    public static void m558a(Drawable drawable, Theme theme) {
        drawable.applyTheme(theme);
    }

    public static void m559a(Drawable drawable, Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Theme theme) {
        drawable.inflate(resources, xmlPullParser, attributeSet, theme);
    }

    public static void m560a(Drawable drawable, Mode mode) {
        drawable.setTintMode(mode);
    }

    public static boolean m561b(Drawable drawable) {
        return drawable.canApplyTheme();
    }

    public static ColorFilter m562c(Drawable drawable) {
        return drawable.getColorFilter();
    }
}
