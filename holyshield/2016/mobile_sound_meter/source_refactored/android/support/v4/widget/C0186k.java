package android.support.v4.widget;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.widget.CompoundButton;
import java.lang.reflect.Field;

/* renamed from: android.support.v4.widget.k */
class C0186k {
    private static Field f558a;
    private static boolean f559b;

    static Drawable m1555a(CompoundButton compoundButton) {
        if (!f559b) {
            try {
                f558a = CompoundButton.class.getDeclaredField("mButtonDrawable");
                f558a.setAccessible(true);
            } catch (Throwable e) {
                Log.i("CompoundButtonCompatDonut", "Failed to retrieve mButtonDrawable field", e);
            }
            f559b = true;
        }
        if (f558a != null) {
            try {
                return (Drawable) f558a.get(compoundButton);
            } catch (Throwable e2) {
                Log.i("CompoundButtonCompatDonut", "Failed to get button drawable via reflection", e2);
                f558a = null;
            }
        }
        return null;
    }

    static void m1556a(CompoundButton compoundButton, ColorStateList colorStateList) {
        if (compoundButton instanceof ba) {
            ((ba) compoundButton).setSupportButtonTintList(colorStateList);
        }
    }

    static void m1557a(CompoundButton compoundButton, Mode mode) {
        if (compoundButton instanceof ba) {
            ((ba) compoundButton).setSupportButtonTintMode(mode);
        }
    }
}
