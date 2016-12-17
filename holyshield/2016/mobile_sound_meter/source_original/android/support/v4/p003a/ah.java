package android.support.v4.p003a;

import android.view.View;
import android.view.animation.Animation;

/* renamed from: android.support.v4.a.ah */
class ah extends ai {
    final /* synthetic */ C0042t f134a;
    final /* synthetic */ af f135b;

    ah(af afVar, View view, Animation animation, C0042t c0042t) {
        this.f135b = afVar;
        this.f134a = c0042t;
        super(view, animation);
    }

    public void onAnimationEnd(Animation animation) {
        super.onAnimationEnd(animation);
        if (this.f134a.f293c != null) {
            this.f134a.f293c = null;
            this.f135b.m163a(this.f134a, this.f134a.f294d, 0, 0, false);
        }
    }
}
