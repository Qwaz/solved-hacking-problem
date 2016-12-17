package android.support.v4.p004h;

import android.view.LayoutInflater;
import android.view.LayoutInflater.Factory;

/* renamed from: android.support.v4.h.ag */
class ag {
    static al m845a(LayoutInflater layoutInflater) {
        Factory factory = layoutInflater.getFactory();
        return factory instanceof ah ? ((ah) factory).f430a : null;
    }

    static void m846a(LayoutInflater layoutInflater, al alVar) {
        layoutInflater.setFactory(alVar != null ? new ah(alVar) : null);
    }
}
