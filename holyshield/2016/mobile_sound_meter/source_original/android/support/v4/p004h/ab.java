package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.LayoutInflater;

/* renamed from: android.support.v4.h.ab */
public final class ab {
    static final ac f429a;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 21) {
            f429a = new af();
        } else if (i >= 11) {
            f429a = new ae();
        } else {
            f429a = new ad();
        }
    }

    public static al m837a(LayoutInflater layoutInflater) {
        return f429a.m839a(layoutInflater);
    }

    public static void m838a(LayoutInflater layoutInflater, al alVar) {
        f429a.m840a(layoutInflater, alVar);
    }
}
