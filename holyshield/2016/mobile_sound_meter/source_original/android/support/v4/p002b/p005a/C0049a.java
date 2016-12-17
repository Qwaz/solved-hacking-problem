package android.support.v4.p002b.p005a;

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;

/* renamed from: android.support.v4.b.a.a */
public final class C0049a {
    public static Drawable m430a(Resources resources, int i, Theme theme) {
        return VERSION.SDK_INT >= 21 ? C0050b.m431a(resources, i, theme) : resources.getDrawable(i);
    }
}
