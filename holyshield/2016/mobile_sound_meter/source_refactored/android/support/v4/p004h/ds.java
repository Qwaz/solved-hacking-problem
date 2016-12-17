package android.support.v4.p004h;

import android.view.View;
import android.view.animation.Interpolator;

/* renamed from: android.support.v4.h.ds */
class ds {
    public static long m1275a(View view) {
        return view.animate().getDuration();
    }

    public static void m1276a(View view, float f) {
        view.animate().alpha(f);
    }

    public static void m1277a(View view, long j) {
        view.animate().setDuration(j);
    }

    public static void m1278a(View view, dy dyVar) {
        if (dyVar != null) {
            view.animate().setListener(new dt(dyVar, view));
        } else {
            view.animate().setListener(null);
        }
    }

    public static void m1279a(View view, Interpolator interpolator) {
        view.animate().setInterpolator(interpolator);
    }

    public static void m1280b(View view) {
        view.animate().cancel();
    }

    public static void m1281b(View view, float f) {
        view.animate().translationY(f);
    }

    public static void m1282b(View view, long j) {
        view.animate().setStartDelay(j);
    }

    public static void m1283c(View view) {
        view.animate().start();
    }
}
