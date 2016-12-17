package android.support.v4.p004h;

import android.animation.ValueAnimator;
import android.graphics.Paint;
import android.view.View;

/* renamed from: android.support.v4.h.ck */
class ck {
    public static int m1142a(int i, int i2, int i3) {
        return View.resolveSizeAndState(i, i2, i3);
    }

    public static int m1143a(View view) {
        return view.getLayerType();
    }

    static long m1144a() {
        return ValueAnimator.getFrameDelay();
    }

    public static void m1145a(View view, float f) {
        view.setTranslationY(f);
    }

    public static void m1146a(View view, int i, Paint paint) {
        view.setLayerType(i, paint);
    }

    public static void m1147a(View view, boolean z) {
        view.setSaveFromParentEnabled(z);
    }

    public static int m1148b(View view) {
        return view.getMeasuredWidthAndState();
    }

    public static void m1149b(View view, float f) {
        view.setAlpha(f);
    }

    public static void m1150b(View view, boolean z) {
        view.setActivated(z);
    }

    public static int m1151c(View view) {
        return view.getMeasuredState();
    }

    public static float m1152d(View view) {
        return view.getTranslationY();
    }

    public static void m1153e(View view) {
        view.jumpDrawablesToCurrentState();
    }
}
