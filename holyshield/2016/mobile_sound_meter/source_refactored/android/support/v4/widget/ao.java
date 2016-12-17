package android.support.v4.widget;

import android.util.Log;
import android.widget.PopupWindow;
import java.lang.reflect.Field;

class ao {
    private static Field f528a;

    static {
        try {
            f528a = PopupWindow.class.getDeclaredField("mOverlapAnchor");
            f528a.setAccessible(true);
        } catch (Throwable e) {
            Log.i("PopupWindowCompatApi21", "Could not fetch mOverlapAnchor field from PopupWindow", e);
        }
    }

    static void m1446a(PopupWindow popupWindow, boolean z) {
        if (f528a != null) {
            try {
                f528a.set(popupWindow, Boolean.valueOf(z));
            } catch (Throwable e) {
                Log.i("PopupWindowCompatApi21", "Could not set overlap anchor field in PopupWindow", e);
            }
        }
    }
}
