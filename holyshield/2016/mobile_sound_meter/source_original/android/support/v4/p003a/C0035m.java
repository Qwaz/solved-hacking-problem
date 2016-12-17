package android.support.v4.p003a;

import android.view.View;
import android.view.ViewTreeObserver.OnPreDrawListener;

/* renamed from: android.support.v4.a.m */
class C0035m implements OnPreDrawListener {
    final /* synthetic */ View f235a;
    final /* synthetic */ C0037o f236b;
    final /* synthetic */ int f237c;
    final /* synthetic */ Object f238d;
    final /* synthetic */ C0032j f239e;

    C0035m(C0032j c0032j, View view, C0037o c0037o, int i, Object obj) {
        this.f239e = c0032j;
        this.f235a = view;
        this.f236b = c0037o;
        this.f237c = i;
        this.f238d = obj;
    }

    public boolean onPreDraw() {
        this.f235a.getViewTreeObserver().removeOnPreDrawListener(this);
        this.f239e.m311a(this.f236b, this.f237c, this.f238d);
        return true;
    }
}
