package android.support.v7.p014a;

import android.content.Context;
import android.support.v7.widget.ContentFrameLayout;
import android.support.v7.widget.ao;
import android.view.KeyEvent;
import android.view.MotionEvent;

/* renamed from: android.support.v7.a.ap */
class ap extends ContentFrameLayout {
    final /* synthetic */ ae f634a;

    public ap(ae aeVar, Context context) {
        this.f634a = aeVar;
        super(context);
    }

    private boolean m1769a(int i, int i2) {
        return i < -5 || i2 < -5 || i > getWidth() + 5 || i2 > getHeight() + 5;
    }

    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        return this.f634a.m1712a(keyEvent) || super.dispatchKeyEvent(keyEvent);
    }

    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (motionEvent.getAction() != 0 || !m1769a((int) motionEvent.getX(), (int) motionEvent.getY())) {
            return super.onInterceptTouchEvent(motionEvent);
        }
        this.f634a.m1686d(0);
        return true;
    }

    public void setBackgroundResource(int i) {
        setBackgroundDrawable(ao.m2497a().m2520a(getContext(), i));
    }
}
