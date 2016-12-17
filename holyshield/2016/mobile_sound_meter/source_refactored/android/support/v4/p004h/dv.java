package android.support.v4.p004h;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;

/* renamed from: android.support.v4.h.dv */
final class dv extends AnimatorListenerAdapter {
    final /* synthetic */ dy f467a;
    final /* synthetic */ View f468b;

    dv(dy dyVar, View view) {
        this.f467a = dyVar;
        this.f468b = view;
    }

    public void onAnimationCancel(Animator animator) {
        this.f467a.m1269c(this.f468b);
    }

    public void onAnimationEnd(Animator animator) {
        this.f467a.m1268b(this.f468b);
    }

    public void onAnimationStart(Animator animator) {
        this.f467a.m1267a(this.f468b);
    }
}
