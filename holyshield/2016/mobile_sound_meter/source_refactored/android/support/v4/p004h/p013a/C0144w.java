package android.support.v4.p004h.p013a;

import android.os.Bundle;
import java.util.ArrayList;
import java.util.List;

/* renamed from: android.support.v4.h.a.w */
class C0144w implements ad {
    final /* synthetic */ C0138r f423a;
    final /* synthetic */ C0143v f424b;

    C0144w(C0143v c0143v, C0138r c0138r) {
        this.f424b = c0143v;
        this.f423a = c0138r;
    }

    public Object m820a(int i) {
        C0126f a = this.f423a.m808a(i);
        return a == null ? null : a.m702a();
    }

    public List m821a(String str, int i) {
        List a = this.f423a.m810a(str, i);
        List arrayList = new ArrayList();
        int size = a.size();
        for (int i2 = 0; i2 < size; i2++) {
            arrayList.add(((C0126f) a.get(i2)).m702a());
        }
        return arrayList;
    }

    public boolean m822a(int i, int i2, Bundle bundle) {
        return this.f423a.m811a(i, i2, bundle);
    }

    public Object m823b(int i) {
        C0126f b = this.f423a.m812b(i);
        return b == null ? null : b.m702a();
    }
}
