package android.support.v4.p004h.p013a;

import android.os.Bundle;
import java.util.ArrayList;
import java.util.List;

/* renamed from: android.support.v4.h.a.u */
class C0142u implements aa {
    final /* synthetic */ C0138r f421a;
    final /* synthetic */ C0141t f422b;

    C0142u(C0141t c0141t, C0138r c0138r) {
        this.f422b = c0141t;
        this.f421a = c0138r;
    }

    public Object m816a(int i) {
        C0126f a = this.f421a.m808a(i);
        return a == null ? null : a.m702a();
    }

    public List m817a(String str, int i) {
        List a = this.f421a.m810a(str, i);
        List arrayList = new ArrayList();
        int size = a.size();
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(((C0126f) a.get(i2)).m702a());
        }
        return arrayList;
    }

    public boolean m818a(int i, int i2, Bundle bundle) {
        return this.f421a.m811a(i, i2, bundle);
    }
}
