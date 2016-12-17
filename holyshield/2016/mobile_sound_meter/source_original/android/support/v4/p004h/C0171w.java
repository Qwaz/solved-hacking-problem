package android.support.v4.p004h;

/* renamed from: android.support.v4.h.w */
class C0171w implements C0170z {
    C0171w() {
    }

    private static int m1354a(int i, int i2, int i3, int i4, int i5) {
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

    public int m1355a(int i) {
        int i2 = (i & 192) != 0 ? i | 1 : i;
        if ((i2 & 48) != 0) {
            i2 |= 2;
        }
        return i2 & 247;
    }

    public boolean m1356a(int i, int i2) {
        return C0171w.m1354a(C0171w.m1354a(m1355a(i) & 247, i2, 1, 64, 128), i2, 2, 16, 32) == i2;
    }
}
