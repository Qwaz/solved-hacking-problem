package android.support.v4.p004h;

import android.animation.ValueAnimator;
import android.animation.ValueAnimator.AnimatorUpdateListener;
import android.view.View;

/* renamed from: android.support.v4.h.dx */
final class dx implements AnimatorUpdateListener {
    final /* synthetic */ ea f469a;
    final /* synthetic */ View f470b;

    dx(ea eaVar, View view) {
        this.f469a = eaVar;
        this.f470b = view;
    }

    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        this.f469a.m1292a(this.f470b);
    }
}
