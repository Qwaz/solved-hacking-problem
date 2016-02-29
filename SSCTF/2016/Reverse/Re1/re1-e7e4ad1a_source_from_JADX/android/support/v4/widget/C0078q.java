package android.support.v4.widget;

import android.support.v4.view.C0061x;
import android.view.View;

/* renamed from: android.support.v4.widget.q */
class C0078q implements Runnable {
    final View f324a;
    final /* synthetic */ SlidingPaneLayout f325b;

    C0078q(SlidingPaneLayout slidingPaneLayout, View view) {
        this.f325b = slidingPaneLayout;
        this.f324a = view;
    }

    public void run() {
        if (this.f324a.getParent() == this.f325b) {
            C0061x.m381a(this.f324a, 0, null);
            this.f325b.m421d(this.f324a);
        }
        this.f325b.f311t.remove(this);
    }
}
