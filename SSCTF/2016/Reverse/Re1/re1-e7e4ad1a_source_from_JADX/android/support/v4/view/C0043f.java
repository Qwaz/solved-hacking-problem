package android.support.v4.view;

import android.os.Build.VERSION;
import android.view.KeyEvent;

/* renamed from: android.support.v4.view.f */
public class C0043f {
    static final C0044j f262a;

    static {
        if (VERSION.SDK_INT >= 11) {
            f262a = new C0047i();
        } else {
            f262a = new C0045g();
        }
    }

    public static boolean m305a(KeyEvent keyEvent) {
        return f262a.m310b(keyEvent.getMetaState());
    }

    public static boolean m306a(KeyEvent keyEvent, int i) {
        return f262a.m309a(keyEvent.getMetaState(), i);
    }

    public static void m307b(KeyEvent keyEvent) {
        f262a.m308a(keyEvent);
    }
}
