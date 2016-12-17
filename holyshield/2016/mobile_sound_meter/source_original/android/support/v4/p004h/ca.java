package android.support.v4.p004h;

import android.view.View;
import java.util.WeakHashMap;

/* renamed from: android.support.v4.h.ca */
class ca extends by {
    static boolean f445b;

    static {
        f445b = false;
    }

    ca() {
    }

    public void m1096a(View view, C0147a c0147a) {
        cl.m1154a(view, c0147a == null ? null : c0147a.m826a());
    }

    public boolean m1097a(View view, int i) {
        return cl.m1155a(view, i);
    }

    public dh m1098j(View view) {
        if (this.a == null) {
            this.a = new WeakHashMap();
        }
        dh dhVar = (dh) this.a.get(view);
        if (dhVar != null) {
            return dhVar;
        }
        dhVar = new dh(view);
        this.a.put(view, dhVar);
        return dhVar;
    }
}
