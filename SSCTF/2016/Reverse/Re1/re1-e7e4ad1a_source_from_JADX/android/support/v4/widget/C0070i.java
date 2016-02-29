package android.support.v4.widget;

import android.graphics.Canvas;
import android.widget.EdgeEffect;

/* renamed from: android.support.v4.widget.i */
class C0070i {
    public static void m486a(Object obj, int i, int i2) {
        ((EdgeEffect) obj).setSize(i, i2);
    }

    public static boolean m487a(Object obj) {
        return ((EdgeEffect) obj).isFinished();
    }

    public static boolean m488a(Object obj, float f) {
        ((EdgeEffect) obj).onPull(f);
        return true;
    }

    public static boolean m489a(Object obj, Canvas canvas) {
        return ((EdgeEffect) obj).draw(canvas);
    }

    public static void m490b(Object obj) {
        ((EdgeEffect) obj).finish();
    }

    public static boolean m491c(Object obj) {
        EdgeEffect edgeEffect = (EdgeEffect) obj;
        edgeEffect.onRelease();
        return edgeEffect.isFinished();
    }
}
