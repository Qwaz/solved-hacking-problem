package android.support.v7.widget;

import android.view.ViewTreeObserver.OnGlobalLayoutListener;

class bl implements OnGlobalLayoutListener {
    final /* synthetic */ bj f1407a;

    bl(bj bjVar) {
        this.f1407a = bjVar;
    }

    public void onGlobalLayout() {
        if (this.f1407a.m2587b(this.f1407a.f1401a)) {
            this.f1407a.m2591b();
            super.m2567c();
            return;
        }
        this.f1407a.m2579i();
    }
}
