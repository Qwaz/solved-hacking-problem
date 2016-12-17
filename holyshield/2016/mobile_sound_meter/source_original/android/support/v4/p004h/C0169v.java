package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.KeyEvent;

/* renamed from: android.support.v4.h.v */
public final class C0169v {
    static final C0170z f480a;

    static {
        if (VERSION.SDK_INT >= 11) {
            f480a = new C0173y();
        } else {
            f480a = new C0171w();
        }
    }

    public static boolean m1352a(KeyEvent keyEvent, int i) {
        return f480a.m1353a(keyEvent.getMetaState(), i);
    }
}
