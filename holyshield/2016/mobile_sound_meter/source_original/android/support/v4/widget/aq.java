package android.support.v4.widget;

import android.widget.PopupWindow;
import java.lang.reflect.Method;

class aq {
    private static Method f529a;
    private static boolean f530b;

    static void m1449a(PopupWindow popupWindow, int i) {
        if (!f530b) {
            try {
                f529a = PopupWindow.class.getDeclaredMethod("setWindowLayoutType", new Class[]{Integer.TYPE});
                f529a.setAccessible(true);
            } catch (Exception e) {
            }
            f530b = true;
        }
        if (f529a != null) {
            try {
                f529a.invoke(popupWindow, new Object[]{Integer.valueOf(i)});
            } catch (Exception e2) {
            }
        }
    }
}
