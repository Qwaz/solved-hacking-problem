package android.support.v4.view;

import android.view.View;

class ak {
    public static void m285a(View view) {
        view.postInvalidateOnAnimation();
    }

    public static void m286a(View view, int i, int i2, int i3, int i4) {
        view.postInvalidate(i, i2, i3, i4);
    }

    public static void m287a(View view, Runnable runnable) {
        view.postOnAnimation(runnable);
    }
}
