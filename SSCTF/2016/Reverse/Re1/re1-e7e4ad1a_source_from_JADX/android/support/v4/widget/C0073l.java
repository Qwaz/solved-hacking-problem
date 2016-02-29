package android.support.v4.widget;

import android.widget.Scroller;

/* renamed from: android.support.v4.widget.l */
class C0073l implements C0072k {
    C0073l() {
    }

    public void m508a(Object obj, int i, int i2, int i3, int i4, int i5) {
        ((Scroller) obj).startScroll(i, i2, i3, i4, i5);
    }

    public boolean m509a(Object obj) {
        return ((Scroller) obj).isFinished();
    }

    public int m510b(Object obj) {
        return ((Scroller) obj).getCurrX();
    }

    public int m511c(Object obj) {
        return ((Scroller) obj).getCurrY();
    }

    public boolean m512d(Object obj) {
        return ((Scroller) obj).computeScrollOffset();
    }

    public void m513e(Object obj) {
        ((Scroller) obj).abortAnimation();
    }

    public int m514f(Object obj) {
        return ((Scroller) obj).getFinalX();
    }

    public int m515g(Object obj) {
        return ((Scroller) obj).getFinalY();
    }
}
