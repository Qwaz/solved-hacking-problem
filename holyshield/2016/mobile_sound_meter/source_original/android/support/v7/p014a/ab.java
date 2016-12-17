package android.support.v7.p014a;

import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.support.v7.view.C0252h;
import android.view.ActionMode;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.ab */
class ab extends C0206y {
    final /* synthetic */ aa f612b;

    ab(aa aaVar, Callback callback) {
        this.f612b = aaVar;
        super(aaVar, callback);
    }

    final ActionMode m1740a(ActionMode.Callback callback) {
        Object c0252h = new C0252h(this.f612b.a, callback);
        C0212b b = this.f612b.m1713b((C0208c) c0252h);
        return b != null ? c0252h.m2020b(b) : null;
    }

    public ActionMode onWindowStartingActionMode(ActionMode.Callback callback) {
        return this.f612b.m1739m() ? m1740a(callback) : super.onWindowStartingActionMode(callback);
    }
}
