package android.support.v4.widget;

import android.widget.OverScroller;

/* renamed from: android.support.v4.widget.o */
class C0076o {
    public static void m524a(Object obj, int i, int i2, int i3, int i4, int i5) {
        ((OverScroller) obj).startScroll(i, i2, i3, i4, i5);
    }

    public static boolean m525a(Object obj) {
        return ((OverScroller) obj).isFinished();
    }

    public static int m526b(Object obj) {
        return ((OverScroller) obj).getCurrX();
    }

    public static int m527c(Object obj) {
        return ((OverScroller) obj).getCurrY();
    }

    public static boolean m528d(Object obj) {
        return ((OverScroller) obj).computeScrollOffset();
    }

    public static void m529e(Object obj) {
        ((OverScroller) obj).abortAnimation();
    }

    public static int m530f(Object obj) {
        return ((OverScroller) obj).getFinalX();
    }

    public static int m531g(Object obj) {
        return ((OverScroller) obj).getFinalY();
    }
}
