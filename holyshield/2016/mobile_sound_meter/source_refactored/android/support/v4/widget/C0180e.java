package android.support.v4.widget;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.widget.CompoundButton;

/* renamed from: android.support.v4.widget.e */
public final class C0180e {
    private static final C0181h f557a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 23) {
            f557a = new C0184f();
        } else if (i >= 21) {
            f557a = new C0183i();
        } else {
            f557a = new C0182g();
        }
    }

    public static Drawable m1542a(CompoundButton compoundButton) {
        return f557a.m1545a(compoundButton);
    }

    public static void m1543a(CompoundButton compoundButton, ColorStateList colorStateList) {
        f557a.m1546a(compoundButton, colorStateList);
    }

    public static void m1544a(CompoundButton compoundButton, Mode mode) {
        f557a.m1547a(compoundButton, mode);
    }
}
