package android.support.v4.p004h;

import android.view.View;

/* renamed from: android.support.v4.h.cn */
class cn {
    public static void m1157a(View view) {
        view.postInvalidateOnAnimation();
    }

    public static void m1158a(View view, Runnable runnable) {
        view.postOnAnimation(runnable);
    }

    public static void m1159a(View view, Runnable runnable, long j) {
        view.postOnAnimationDelayed(runnable, j);
    }

    public static int m1160b(View view) {
        return view.getMinimumHeight();
    }

    public static void m1161c(View view) {
        view.requestFitSystemWindows();
    }

    public static boolean m1162d(View view) {
        return view.hasOverlappingRendering();
    }
}
