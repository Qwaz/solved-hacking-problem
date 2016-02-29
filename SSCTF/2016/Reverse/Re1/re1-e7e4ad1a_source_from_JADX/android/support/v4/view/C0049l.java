package android.support.v4.view;

import android.view.KeyEvent;

/* renamed from: android.support.v4.view.l */
class C0049l {
    public static int m321a(int i) {
        return KeyEvent.normalizeMetaState(i);
    }

    public static boolean m322a(int i, int i2) {
        return KeyEvent.metaStateHasModifiers(i, i2);
    }

    public static boolean m323b(int i) {
        return KeyEvent.metaStateHasNoModifiers(i);
    }
}
