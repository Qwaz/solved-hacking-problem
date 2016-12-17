package android.support.v4.p003a;

import android.support.v4.p012g.C0107a;
import android.view.View;
import android.view.ViewTreeObserver.OnPreDrawListener;
import java.util.ArrayList;
import java.util.Map;

/* renamed from: android.support.v4.a.l */
class C0034l implements OnPreDrawListener {
    final /* synthetic */ View f227a;
    final /* synthetic */ Object f228b;
    final /* synthetic */ ArrayList f229c;
    final /* synthetic */ C0037o f230d;
    final /* synthetic */ boolean f231e;
    final /* synthetic */ C0042t f232f;
    final /* synthetic */ C0042t f233g;
    final /* synthetic */ C0032j f234h;

    C0034l(C0032j c0032j, View view, Object obj, ArrayList arrayList, C0037o c0037o, boolean z, C0042t c0042t, C0042t c0042t2) {
        this.f234h = c0032j;
        this.f227a = view;
        this.f228b = obj;
        this.f229c = arrayList;
        this.f230d = c0037o;
        this.f231e = z;
        this.f232f = c0042t;
        this.f233g = c0042t2;
    }

    public boolean onPreDraw() {
        this.f227a.getViewTreeObserver().removeOnPreDrawListener(this);
        if (this.f228b != null) {
            ar.m219a(this.f228b, this.f229c);
            this.f229c.clear();
            C0107a a = this.f234h.m303a(this.f230d, this.f231e, this.f232f);
            ar.m216a(this.f228b, this.f230d.f252d, (Map) a, this.f229c);
            this.f234h.m316a(a, this.f230d);
            this.f234h.m312a(this.f230d, this.f232f, this.f233g, this.f231e, a);
        }
        return true;
    }
}
