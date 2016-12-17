package android.support.v4.p004h;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.view.View;

/* renamed from: android.support.v4.h.dt */
final class dt extends AnimatorListenerAdapter {
    final /* synthetic */ dy f465a;
    final /* synthetic */ View f466b;

    dt(dy dyVar, View view) {
        this.f465a = dyVar;
        this.f466b = view;
    }

    public void onAnimationCancel(Animator animator) {
        this.f465a.m1269c(this.f466b);
    }

    public void onAnimationEnd(Animator animator) {
        this.f465a.m1268b(this.f466b);
    }

    public void onAnimationStart(Animator animator) {
        this.f465a.m1267a(this.f466b);
    }
}
