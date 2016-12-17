package android.support.p000a.p001a;

import java.util.ArrayList;

/* renamed from: android.support.a.a.f */
class C0006f {
    private static int m7a(String str, int i) {
        while (i < str.length()) {
            char charAt = str.charAt(i);
            if (((charAt - 65) * (charAt - 90) <= 0 || (charAt - 97) * (charAt - 122) <= 0) && charAt != 'e' && charAt != 'E') {
                break;
            }
            i++;
        }
        return i;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private static void m8a(java.lang.String r7, int r8, android.support.p000a.p001a.C0008h r9) {
        /*
        r1 = 0;
        r5 = 1;
        r9.f18b = r1;
        r0 = r1;
        r2 = r1;
        r3 = r1;
        r4 = r8;
    L_0x0008:
        r6 = r7.length();
        if (r4 >= r6) goto L_0x0018;
    L_0x000e:
        r6 = r7.charAt(r4);
        switch(r6) {
            case 32: goto L_0x001b;
            case 44: goto L_0x001b;
            case 45: goto L_0x001e;
            case 46: goto L_0x0027;
            case 69: goto L_0x0031;
            case 101: goto L_0x0031;
            default: goto L_0x0015;
        };
    L_0x0015:
        r0 = r1;
    L_0x0016:
        if (r3 == 0) goto L_0x0033;
    L_0x0018:
        r9.f17a = r4;
        return;
    L_0x001b:
        r0 = r1;
        r3 = r5;
        goto L_0x0016;
    L_0x001e:
        if (r4 == r8) goto L_0x0015;
    L_0x0020:
        if (r0 != 0) goto L_0x0015;
    L_0x0022:
        r9.f18b = r5;
        r0 = r1;
        r3 = r5;
        goto L_0x0016;
    L_0x0027:
        if (r2 != 0) goto L_0x002c;
    L_0x0029:
        r0 = r1;
        r2 = r5;
        goto L_0x0016;
    L_0x002c:
        r9.f18b = r5;
        r0 = r1;
        r3 = r5;
        goto L_0x0016;
    L_0x0031:
        r0 = r5;
        goto L_0x0016;
    L_0x0033:
        r4 = r4 + 1;
        goto L_0x0008;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.a.a.f.a(java.lang.String, int, android.support.a.a.h):void");
    }

    private static void m9a(ArrayList arrayList, char c, float[] fArr) {
        arrayList.add(new C0009i(fArr, null));
    }

    public static C0009i[] m11a(String str) {
        if (str == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        int i = 1;
        int i2 = 0;
        while (i < str.length()) {
            int a = C0006f.m7a(str, i);
            String trim = str.substring(i2, a).trim();
            if (trim.length() > 0) {
                C0006f.m9a(arrayList, trim.charAt(0), C0006f.m13b(trim));
            }
            i = a + 1;
            i2 = a;
        }
        if (i - i2 == 1 && i2 < str.length()) {
            C0006f.m9a(arrayList, str.charAt(i2), new float[0]);
        }
        return (C0009i[]) arrayList.toArray(new C0009i[arrayList.size()]);
    }

    public static C0009i[] m12a(C0009i[] c0009iArr) {
        if (c0009iArr == null) {
            return null;
        }
        C0009i[] c0009iArr2 = new C0009i[c0009iArr.length];
        for (int i = 0; i < c0009iArr.length; i++) {
            c0009iArr2[i] = new C0009i(null);
        }
        return c0009iArr2;
    }

    private static float[] m13b(String str) {
        if (((str.charAt(0) == 'z' ? 1 : 0) | (str.charAt(0) == 'Z' ? 1 : 0)) != 0) {
            return new float[0];
        }
        try {
            float[] fArr = new float[str.length()];
            C0008h c0008h = new C0008h();
            int length = str.length();
            int i = 0;
            int i2 = 1;
            while (i2 < length) {
                int i3;
                C0006f.m8a(str, i2, c0008h);
                int i4 = c0008h.f17a;
                if (i2 < i4) {
                    i3 = i + 1;
                    fArr[i] = Float.parseFloat(str.substring(i2, i4));
                } else {
                    i3 = i;
                }
                if (c0008h.f18b) {
                    i2 = i4;
                    i = i3;
                } else {
                    i2 = i4 + 1;
                    i = i3;
                }
            }
            return C0006f.m14b(fArr, 0, i);
        } catch (Throwable e) {
            throw new RuntimeException("error in parsing \"" + str + "\"", e);
        }
    }

    private static float[] m14b(float[] fArr, int i, int i2) {
        if (i > i2) {
            throw new IllegalArgumentException();
        }
        int length = fArr.length;
        if (i < 0 || i > length) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int i3 = i2 - i;
        length = Math.min(i3, length - i);
        Object obj = new float[i3];
        System.arraycopy(fArr, i, obj, 0, length);
        return obj;
    }
}
