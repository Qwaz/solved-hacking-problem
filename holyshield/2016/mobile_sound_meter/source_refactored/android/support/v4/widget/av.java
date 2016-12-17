package android.support.v4.widget;

import android.content.Context;
import android.view.animation.Interpolator;
import android.widget.Scroller;

class av implements au {
    av() {
    }

    public Object m1492a(Context context, Interpolator interpolator) {
        return interpolator != null ? new Scroller(context, interpolator) : new Scroller(context);
    }

    public void m1493a(Object obj, int i, int i2, int i3, int i4) {
        ((Scroller) obj).startScroll(i, i2, i3, i4);
    }

    public void m1494a(Object obj, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        ((Scroller) obj).fling(i, i2, i3, i4, i5, i6, i7, i8);
    }

    public void m1495a(Object obj, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
        ((Scroller) obj).fling(i, i2, i3, i4, i5, i6, i7, i8);
    }

    public boolean m1496a(Object obj) {
        return ((Scroller) obj).isFinished();
    }

    public boolean m1497a(Object obj, int i, int i2, int i3, int i4, int i5, int i6) {
        return false;
    }

    public int m1498b(Object obj) {
        return ((Scroller) obj).getCurrX();
    }

    public int m1499c(Object obj) {
        return ((Scroller) obj).getCurrY();
    }

    public float m1500d(Object obj) {
        return 0.0f;
    }

    public boolean m1501e(Object obj) {
        return ((Scroller) obj).computeScrollOffset();
    }

    public void m1502f(Object obj) {
        ((Scroller) obj).abortAnimation();
    }

    public int m1503g(Object obj) {
        return ((Scroller) obj).getFinalY();
    }
}
