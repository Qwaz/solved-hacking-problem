package android.support.v4.app;

import android.view.animation.Animation;
import android.view.animation.Animation.AnimationListener;

/* renamed from: android.support.v4.app.p */
class C0018p implements AnimationListener {
    final /* synthetic */ Fragment f159a;
    final /* synthetic */ C0016n f160b;

    C0018p(C0016n c0016n, Fragment fragment) {
        this.f160b = c0016n;
        this.f159a = fragment;
    }

    public void onAnimationEnd(Animation animation) {
        if (this.f159a.f34b != null) {
            this.f159a.f34b = null;
            this.f160b.m125a(this.f159a, this.f159a.f35c, 0, 0, false);
        }
    }

    public void onAnimationRepeat(Animation animation) {
    }

    public void onAnimationStart(Animation animation) {
    }
}
