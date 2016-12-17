package android.support.v4.p004h;

import android.view.KeyEvent;

/* renamed from: android.support.v4.h.aa */
class aa {
    public static int m835a(int i) {
        return KeyEvent.normalizeMetaState(i);
    }

    public static boolean m836a(int i, int i2) {
        return KeyEvent.metaStateHasModifiers(i, i2);
    }
}
