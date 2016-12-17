package android.support.v4.p006c.p007a;

import android.graphics.drawable.Drawable;
import android.util.Log;
import java.lang.reflect.Method;

/* renamed from: android.support.v4.c.a.n */
class C0080n {
    private static Method f355a;
    private static boolean f356b;

    public static int m548a(Drawable drawable) {
        if (!f356b) {
            try {
                f355a = Drawable.class.getDeclaredMethod("getLayoutDirection", new Class[0]);
                f355a.setAccessible(true);
            } catch (Throwable e) {
                Log.i("DrawableCompatJellybeanMr1", "Failed to retrieve getLayoutDirection() method", e);
            }
            f356b = true;
        }
        if (f355a != null) {
            try {
                return ((Integer) f355a.invoke(drawable, new Object[0])).intValue();
            } catch (Throwable e2) {
                Log.i("DrawableCompatJellybeanMr1", "Failed to invoke getLayoutDirection() via reflection", e2);
                f355a = null;
            }
        }
        return -1;
    }
}
