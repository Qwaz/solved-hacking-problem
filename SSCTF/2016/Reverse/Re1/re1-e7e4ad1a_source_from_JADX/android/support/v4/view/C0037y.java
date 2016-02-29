package android.support.v4.view;

import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;

/* renamed from: android.support.v4.view.y */
class C0037y implements af {
    C0037y() {
    }

    public int m256a(View view) {
        return 2;
    }

    long m257a() {
        return 10;
    }

    public void m258a(View view, int i, int i2, int i3, int i4) {
        view.postInvalidateDelayed(m257a(), i, i2, i3, i4);
    }

    public void m259a(View view, int i, Paint paint) {
    }

    public void m260a(View view, Paint paint) {
    }

    public void m261a(View view, Runnable runnable) {
        view.postDelayed(runnable, m257a());
    }

    public boolean m262a(View view, int i) {
        return false;
    }

    public void m263b(View view) {
        view.postInvalidateDelayed(m257a());
    }

    public int m264c(View view) {
        return 0;
    }

    public int m265d(View view) {
        return 0;
    }

    public boolean m266e(View view) {
        Drawable background = view.getBackground();
        return background != null && background.getOpacity() == -1;
    }
}
