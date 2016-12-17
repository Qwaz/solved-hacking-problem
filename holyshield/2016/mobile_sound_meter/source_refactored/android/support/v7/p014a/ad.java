package android.support.v7.p014a;

import android.support.v7.p015b.C0243l;
import android.view.ActionMode;
import android.view.Window.Callback;

/* renamed from: android.support.v7.a.ad */
class ad extends ab {
    final /* synthetic */ ac f614c;

    ad(ac acVar, Callback callback) {
        this.f614c = acVar;
        super(acVar, callback);
    }

    public ActionMode onWindowStartingActionMode(ActionMode.Callback callback) {
        return null;
    }

    public ActionMode onWindowStartingActionMode(ActionMode.Callback callback, int i) {
        if (this.f614c.m1739m()) {
            switch (i) {
                case C0243l.View_android_theme /*0*/:
                    return m1740a(callback);
            }
        }
        return super.onWindowStartingActionMode(callback, i);
    }
}
