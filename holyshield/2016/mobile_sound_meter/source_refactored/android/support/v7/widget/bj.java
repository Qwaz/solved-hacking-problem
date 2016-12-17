package android.support.v7.widget;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bu;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewTreeObserver;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.widget.ListAdapter;
import android.widget.SpinnerAdapter;

class bj extends by {
    final /* synthetic */ bg f1401a;
    private CharSequence f1402c;
    private ListAdapter f1403d;
    private final Rect f1404e;

    public bj(bg bgVar, Context context, AttributeSet attributeSet, int i) {
        this.f1401a = bgVar;
        super(context, attributeSet, i);
        this.f1404e = new Rect();
        m2561a((View) bgVar);
        m2565a(true);
        m2559a(0);
        m2562a(new bk(this, bgVar));
    }

    private boolean m2587b(View view) {
        return bu.m1009r(view) && view.getGlobalVisibleRect(this.f1404e);
    }

    public CharSequence m2588a() {
        return this.f1402c;
    }

    public void m2589a(ListAdapter listAdapter) {
        super.m2563a(listAdapter);
        this.f1403d = listAdapter;
    }

    public void m2590a(CharSequence charSequence) {
        this.f1402c = charSequence;
    }

    void m2591b() {
        int i;
        Drawable d = m2569d();
        if (d != null) {
            d.getPadding(this.f1401a.f1364l);
            i = du.m2794a(this.f1401a) ? this.f1401a.f1364l.right : -this.f1401a.f1364l.left;
        } else {
            Rect b = this.f1401a.f1364l;
            this.f1401a.f1364l.right = 0;
            b.left = 0;
            i = 0;
        }
        int paddingLeft = this.f1401a.getPaddingLeft();
        int paddingRight = this.f1401a.getPaddingRight();
        int width = this.f1401a.getWidth();
        if (this.f1401a.f1363k == -2) {
            int a = this.f1401a.m2544a((SpinnerAdapter) this.f1403d, m2569d());
            int i2 = (this.f1401a.getContext().getResources().getDisplayMetrics().widthPixels - this.f1401a.f1364l.left) - this.f1401a.f1364l.right;
            if (a <= i2) {
                i2 = a;
            }
            m2574f(Math.max(i2, (width - paddingLeft) - paddingRight));
        } else if (this.f1401a.f1363k == -1) {
            m2574f((width - paddingLeft) - paddingRight);
        } else {
            m2574f(this.f1401a.f1363k);
        }
        m2566b(du.m2794a(this.f1401a) ? ((width - paddingRight) - m2577h()) + i : i + paddingLeft);
    }

    public void m2592c() {
        boolean k = m2581k();
        m2591b();
        m2576g(2);
        super.m2567c();
        m2583m().setChoiceMode(1);
        m2578h(this.f1401a.getSelectedItemPosition());
        if (!k) {
            ViewTreeObserver viewTreeObserver = this.f1401a.getViewTreeObserver();
            if (viewTreeObserver != null) {
                OnGlobalLayoutListener blVar = new bl(this);
                viewTreeObserver.addOnGlobalLayoutListener(blVar);
                m2564a(new bm(this, blVar));
            }
        }
    }
}
