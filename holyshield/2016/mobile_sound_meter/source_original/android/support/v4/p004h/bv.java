package android.support.v4.p004h;

import android.content.res.ColorStateList;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.view.View;
import java.util.WeakHashMap;

/* renamed from: android.support.v4.h.bv */
class bv implements ch {
    WeakHashMap f444a;

    bv() {
        this.f444a = null;
    }

    private boolean m1046a(bn bnVar, int i) {
        int computeVerticalScrollOffset = bnVar.computeVerticalScrollOffset();
        int computeVerticalScrollRange = bnVar.computeVerticalScrollRange() - bnVar.computeVerticalScrollExtent();
        return computeVerticalScrollRange == 0 ? false : i < 0 ? computeVerticalScrollOffset > 0 : computeVerticalScrollOffset < computeVerticalScrollRange + -1;
    }

    public int m1047a(int i, int i2, int i3) {
        return View.resolveSize(i, i2);
    }

    public int m1048a(View view) {
        return 2;
    }

    long m1049a() {
        return 10;
    }

    public eb m1050a(View view, eb ebVar) {
        return ebVar;
    }

    public void m1051a(View view, float f) {
    }

    public void m1052a(View view, int i, int i2) {
    }

    public void m1053a(View view, int i, Paint paint) {
    }

    public void m1054a(View view, ColorStateList colorStateList) {
        ci.m1135a(view, colorStateList);
    }

    public void m1055a(View view, Mode mode) {
        ci.m1136a(view, mode);
    }

    public void m1056a(View view, C0147a c0147a) {
    }

    public void m1057a(View view, bm bmVar) {
    }

    public void m1058a(View view, Runnable runnable) {
        view.postDelayed(runnable, m1049a());
    }

    public void m1059a(View view, Runnable runnable, long j) {
        view.postDelayed(runnable, m1049a() + j);
    }

    public void m1060a(View view, boolean z) {
    }

    public boolean m1061a(View view, int i) {
        return (view instanceof bn) && m1046a((bn) view, i);
    }

    public void m1062b(View view) {
        view.invalidate();
    }

    public void m1063b(View view, float f) {
    }

    public void m1064b(View view, boolean z) {
    }

    public int m1065c(View view) {
        return 0;
    }

    public void m1066c(View view, float f) {
    }

    public int m1067d(View view) {
        return 0;
    }

    public int m1068e(View view) {
        return view.getMeasuredWidth();
    }

    public int m1069f(View view) {
        return 0;
    }

    public boolean m1070g(View view) {
        return true;
    }

    public float m1071h(View view) {
        return 0.0f;
    }

    public int m1072i(View view) {
        return ci.m1139d(view);
    }

    public dh m1073j(View view) {
        return new dh(view);
    }

    public int m1074k(View view) {
        return 0;
    }

    public void m1075l(View view) {
    }

    public void m1076m(View view) {
    }

    public ColorStateList m1077n(View view) {
        return ci.m1134a(view);
    }

    public Mode m1078o(View view) {
        return ci.m1137b(view);
    }

    public void m1079p(View view) {
        if (view instanceof bi) {
            ((bi) view).stopNestedScroll();
        }
    }

    public boolean m1080q(View view) {
        return ci.m1138c(view);
    }

    public boolean m1081r(View view) {
        return ci.m1140e(view);
    }

    public boolean m1082s(View view) {
        return false;
    }
}
