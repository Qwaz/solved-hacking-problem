package android.support.v7.p014a;

import android.support.v4.p004h.bm;
import android.support.v4.p004h.bu;
import android.support.v4.p004h.eb;
import android.view.View;

/* renamed from: android.support.v7.a.ag */
class ag implements bm {
    final /* synthetic */ ae f616a;

    ag(ae aeVar) {
        this.f616a = aeVar;
    }

    public eb m1743a(View view, eb ebVar) {
        int b = ebVar.m1295b();
        int c = this.f616a.m1692g(b);
        if (b != c) {
            ebVar = ebVar.m1294a(ebVar.m1293a(), c, ebVar.m1296c(), ebVar.m1297d());
        }
        return bu.m978a(view, ebVar);
    }
}
