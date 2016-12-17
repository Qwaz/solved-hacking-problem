package android.support.v4.p004h;

import android.view.View;
import android.view.ViewParent;

/* renamed from: android.support.v4.h.df */
class df implements dc {
    df() {
    }

    public void m1197a(ViewParent viewParent, View view) {
        if (viewParent instanceof bk) {
            ((bk) viewParent).onStopNestedScroll(view);
        }
    }

    public void m1198a(ViewParent viewParent, View view, int i, int i2, int i3, int i4) {
        if (viewParent instanceof bk) {
            ((bk) viewParent).onNestedScroll(view, i, i2, i3, i4);
        }
    }

    public void m1199a(ViewParent viewParent, View view, int i, int i2, int[] iArr) {
        if (viewParent instanceof bk) {
            ((bk) viewParent).onNestedPreScroll(view, i, i2, iArr);
        }
    }

    public boolean m1200a(ViewParent viewParent, View view, float f, float f2) {
        return viewParent instanceof bk ? ((bk) viewParent).onNestedPreFling(view, f, f2) : false;
    }

    public boolean m1201a(ViewParent viewParent, View view, float f, float f2, boolean z) {
        return viewParent instanceof bk ? ((bk) viewParent).onNestedFling(view, f, f2, z) : false;
    }

    public boolean m1202a(ViewParent viewParent, View view, View view2, int i) {
        return viewParent instanceof bk ? ((bk) viewParent).onStartNestedScroll(view, view2, i) : false;
    }

    public void m1203b(ViewParent viewParent, View view, View view2, int i) {
        if (viewParent instanceof bk) {
            ((bk) viewParent).onNestedScrollAccepted(view, view2, i);
        }
    }
}
