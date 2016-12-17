package android.support.v4.p004h;

import android.content.res.ColorStateList;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.os.Build.VERSION;
import android.view.View;

/* renamed from: android.support.v4.h.bu */
public final class bu {
    static final ch f443a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 23) {
            f443a = new cg();
        } else if (i >= 21) {
            f443a = new cf();
        } else if (i >= 19) {
            f443a = new ce();
        } else if (i >= 17) {
            f443a = new cc();
        } else if (i >= 16) {
            f443a = new cb();
        } else if (i >= 15) {
            f443a = new bz();
        } else if (i >= 14) {
            f443a = new ca();
        } else if (i >= 11) {
            f443a = new by();
        } else if (i >= 9) {
            f443a = new bx();
        } else if (i >= 7) {
            f443a = new bw();
        } else {
            f443a = new bv();
        }
    }

    public static int m976a(int i, int i2, int i3) {
        return f443a.m1011a(i, i2, i3);
    }

    public static int m977a(View view) {
        return f443a.m1012a(view);
    }

    public static eb m978a(View view, eb ebVar) {
        return f443a.m1013a(view, ebVar);
    }

    public static void m979a(View view, float f) {
        f443a.m1014a(view, f);
    }

    public static void m980a(View view, int i, int i2) {
        f443a.m1015a(view, i, i2);
    }

    public static void m981a(View view, int i, Paint paint) {
        f443a.m1016a(view, i, paint);
    }

    public static void m982a(View view, ColorStateList colorStateList) {
        f443a.m1017a(view, colorStateList);
    }

    public static void m983a(View view, Mode mode) {
        f443a.m1018a(view, mode);
    }

    public static void m984a(View view, C0147a c0147a) {
        f443a.m1019a(view, c0147a);
    }

    public static void m985a(View view, bm bmVar) {
        f443a.m1020a(view, bmVar);
    }

    public static void m986a(View view, Runnable runnable) {
        f443a.m1021a(view, runnable);
    }

    public static void m987a(View view, Runnable runnable, long j) {
        f443a.m1022a(view, runnable, j);
    }

    public static void m988a(View view, boolean z) {
        f443a.m1023a(view, z);
    }

    public static boolean m989a(View view, int i) {
        return f443a.m1024a(view, i);
    }

    public static void m990b(View view) {
        f443a.m1025b(view);
    }

    public static void m991b(View view, float f) {
        f443a.m1026b(view, f);
    }

    public static void m992b(View view, boolean z) {
        f443a.m1027b(view, z);
    }

    public static int m993c(View view) {
        return f443a.m1028c(view);
    }

    public static void m994c(View view, float f) {
        f443a.m1029c(view, f);
    }

    public static int m995d(View view) {
        return f443a.m1030d(view);
    }

    public static int m996e(View view) {
        return f443a.m1031e(view);
    }

    public static int m997f(View view) {
        return f443a.m1032f(view);
    }

    public static float m998g(View view) {
        return f443a.m1034h(view);
    }

    public static int m999h(View view) {
        return f443a.m1035i(view);
    }

    public static dh m1000i(View view) {
        return f443a.m1036j(view);
    }

    public static int m1001j(View view) {
        return f443a.m1037k(view);
    }

    public static void m1002k(View view) {
        f443a.m1038l(view);
    }

    public static void m1003l(View view) {
        f443a.m1039m(view);
    }

    public static boolean m1004m(View view) {
        return f443a.m1033g(view);
    }

    public static ColorStateList m1005n(View view) {
        return f443a.m1040n(view);
    }

    public static Mode m1006o(View view) {
        return f443a.m1041o(view);
    }

    public static void m1007p(View view) {
        f443a.m1042p(view);
    }

    public static boolean m1008q(View view) {
        return f443a.m1043q(view);
    }

    public static boolean m1009r(View view) {
        return f443a.m1044r(view);
    }

    public static boolean m1010s(View view) {
        return f443a.m1045s(view);
    }
}
