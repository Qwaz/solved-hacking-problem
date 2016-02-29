package android.support.v4.view;

import android.view.KeyEvent;

/* renamed from: android.support.v4.view.g */
class C0045g implements C0044j {
    C0045g() {
    }

    private static int m311a(int i, int i2, int i3, int i4, int i5) {
        Object obj = 1;
        Object obj2 = (i2 & i3) != 0 ? 1 : null;
        int i6 = i4 | i5;
        if ((i2 & i6) == 0) {
            obj = null;
        }
        if (obj2 == null) {
            return obj != null ? i & (i3 ^ -1) : i;
        } else {
            if (obj == null) {
                return i & (i6 ^ -1);
            }
            throw new IllegalArgumentException("bad arguments");
        }
    }

    public int m312a(int i) {
        int i2 = (i & 192) != 0 ? i | 1 : i;
        if ((i2 & 48) != 0) {
            i2 |= 2;
        }
        return i2 & 247;
    }

    public void m313a(KeyEvent keyEvent) {
    }

    public boolean m314a(int i, int i2) {
        return C0045g.m311a(C0045g.m311a(m312a(i) & 247, i2, 1, 64, 128), i2, 2, 16, 32) == i2;
    }

    public boolean m315b(int i) {
        return (m312a(i) & 247) == 0;
    }
}
