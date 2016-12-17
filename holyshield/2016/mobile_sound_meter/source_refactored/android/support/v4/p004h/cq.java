package android.support.v4.p004h;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.view.View;
import android.view.WindowInsets;

/* renamed from: android.support.v4.h.cq */
class cq {
    public static eb m1167a(View view, eb ebVar) {
        if (!(ebVar instanceof ec)) {
            return ebVar;
        }
        WindowInsets e = ((ec) ebVar).m1303e();
        WindowInsets onApplyWindowInsets = view.onApplyWindowInsets(e);
        return onApplyWindowInsets != e ? new ec(onApplyWindowInsets) : ebVar;
    }

    public static void m1168a(View view) {
        view.requestApplyInsets();
    }

    public static void m1169a(View view, float f) {
        view.setElevation(f);
    }

    static void m1170a(View view, ColorStateList colorStateList) {
        view.setBackgroundTintList(colorStateList);
        if (VERSION.SDK_INT == 21) {
            Drawable background = view.getBackground();
            Object obj = (view.getBackgroundTintList() == null || view.getBackgroundTintMode() == null) ? null : 1;
            if (background != null && obj != null) {
                if (background.isStateful()) {
                    background.setState(view.getDrawableState());
                }
                view.setBackground(background);
            }
        }
    }

    static void m1171a(View view, Mode mode) {
        view.setBackgroundTintMode(mode);
        if (VERSION.SDK_INT == 21) {
            Drawable background = view.getBackground();
            Object obj = (view.getBackgroundTintList() == null || view.getBackgroundTintMode() == null) ? null : 1;
            if (background != null && obj != null) {
                if (background.isStateful()) {
                    background.setState(view.getDrawableState());
                }
                view.setBackground(background);
            }
        }
    }

    public static void m1172a(View view, bm bmVar) {
        if (bmVar == null) {
            view.setOnApplyWindowInsetsListener(null);
        } else {
            view.setOnApplyWindowInsetsListener(new cr(bmVar));
        }
    }

    static ColorStateList m1173b(View view) {
        return view.getBackgroundTintList();
    }

    static Mode m1174c(View view) {
        return view.getBackgroundTintMode();
    }

    public static void m1175d(View view) {
        view.stopNestedScroll();
    }
}
