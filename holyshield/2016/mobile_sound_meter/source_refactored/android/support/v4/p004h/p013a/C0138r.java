package android.support.v4.p004h.p013a;

import android.os.Build.VERSION;
import android.os.Bundle;
import java.util.List;

/* renamed from: android.support.v4.h.a.r */
public class C0138r {
    private static final C0139s f419a;
    private final Object f420b;

    static {
        if (VERSION.SDK_INT >= 19) {
            f419a = new C0143v();
        } else if (VERSION.SDK_INT >= 16) {
            f419a = new C0141t();
        } else {
            f419a = new C0140x();
        }
    }

    public C0138r() {
        this.f420b = f419a.m813a(this);
    }

    public C0138r(Object obj) {
        this.f420b = obj;
    }

    public C0126f m808a(int i) {
        return null;
    }

    public Object m809a() {
        return this.f420b;
    }

    public List m810a(String str, int i) {
        return null;
    }

    public boolean m811a(int i, int i2, Bundle bundle) {
        return false;
    }

    public C0126f m812b(int i) {
        return null;
    }
}
