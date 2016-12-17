package android.support.v4.widget;

import android.os.Bundle;
import android.support.v4.p004h.C0147a;
import android.support.v4.p004h.p013a.C0121a;
import android.support.v4.p004h.p013a.C0126f;
import android.support.v4.p004h.p013a.ae;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.widget.ScrollView;

class ad extends C0147a {
    ad() {
    }

    public void m1426a(View view, C0126f c0126f) {
        super.m828a(view, c0126f);
        NestedScrollView nestedScrollView = (NestedScrollView) view;
        c0126f.m705a(ScrollView.class.getName());
        if (nestedScrollView.isEnabled()) {
            int a = nestedScrollView.getScrollRange();
            if (a > 0) {
                c0126f.m706a(true);
                if (nestedScrollView.getScrollY() > 0) {
                    c0126f.m703a(8192);
                }
                if (nestedScrollView.getScrollY() < a) {
                    c0126f.m703a(4096);
                }
            }
        }
    }

    public boolean m1427a(View view, int i, Bundle bundle) {
        if (super.m830a(view, i, bundle)) {
            return true;
        }
        NestedScrollView nestedScrollView = (NestedScrollView) view;
        if (!nestedScrollView.isEnabled()) {
            return false;
        }
        int min;
        switch (i) {
            case 4096:
                min = Math.min(((nestedScrollView.getHeight() - nestedScrollView.getPaddingBottom()) - nestedScrollView.getPaddingTop()) + nestedScrollView.getScrollY(), nestedScrollView.getScrollRange());
                if (min == nestedScrollView.getScrollY()) {
                    return false;
                }
                nestedScrollView.m1384b(0, min);
                return true;
            case 8192:
                min = Math.max(nestedScrollView.getScrollY() - ((nestedScrollView.getHeight() - nestedScrollView.getPaddingBottom()) - nestedScrollView.getPaddingTop()), 0);
                if (min == nestedScrollView.getScrollY()) {
                    return false;
                }
                nestedScrollView.m1384b(0, min);
                return true;
            default:
                return false;
        }
    }

    public void m1428d(View view, AccessibilityEvent accessibilityEvent) {
        super.m834d(view, accessibilityEvent);
        NestedScrollView nestedScrollView = (NestedScrollView) view;
        accessibilityEvent.setClassName(ScrollView.class.getName());
        ae a = C0121a.m667a(accessibilityEvent);
        a.m677a(nestedScrollView.getScrollRange() > 0);
        a.m676a(nestedScrollView.getScrollX());
        a.m678b(nestedScrollView.getScrollY());
        a.m679c(nestedScrollView.getScrollX());
        a.m680d(nestedScrollView.getScrollRange());
    }
}
