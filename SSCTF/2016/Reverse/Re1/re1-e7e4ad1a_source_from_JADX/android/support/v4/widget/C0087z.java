package android.support.v4.widget;

import android.view.animation.Interpolator;

/* renamed from: android.support.v4.widget.z */
final class C0087z implements Interpolator {
    C0087z() {
    }

    public float getInterpolation(float f) {
        float f2 = f - 1.0f;
        return (f2 * (((f2 * f2) * f2) * f2)) + 1.0f;
    }
}
