package android.support.v4.p004h;

import android.view.View;

/* renamed from: android.support.v4.h.du */
class du {
    public static void m1284a(View view, dy dyVar) {
        if (dyVar != null) {
            view.animate().setListener(new dv(dyVar, view));
        } else {
            view.animate().setListener(null);
        }
    }
}
