package android.support.v7.widget;

import android.content.res.Configuration;
import android.os.Build.VERSION;
import android.support.v7.p014a.C0214d;
import android.support.v7.p015b.C0233b;
import android.support.v7.view.C0247a;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.widget.AbsListView.LayoutParams;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.HorizontalScrollView;
import android.widget.Spinner;

public class cp extends HorizontalScrollView implements OnItemSelectedListener {
    private static final Interpolator f1459j;
    Runnable f1460a;
    int f1461b;
    int f1462c;
    private cs f1463d;
    private bw f1464e;
    private Spinner f1465f;
    private boolean f1466g;
    private int f1467h;
    private int f1468i;

    static {
        f1459j = new DecelerateInterpolator();
    }

    private ct m2660a(C0214d c0214d, boolean z) {
        ct ctVar = new ct(this, getContext(), c0214d, z);
        if (z) {
            ctVar.setBackgroundDrawable(null);
            ctVar.setLayoutParams(new LayoutParams(-1, this.f1467h));
        } else {
            ctVar.setFocusable(true);
            if (this.f1463d == null) {
                this.f1463d = new cs();
            }
            ctVar.setOnClickListener(this.f1463d);
        }
        return ctVar;
    }

    private boolean m2662a() {
        return this.f1465f != null && this.f1465f.getParent() == this;
    }

    private void m2663b() {
        if (!m2662a()) {
            if (this.f1465f == null) {
                this.f1465f = m2665d();
            }
            removeView(this.f1464e);
            addView(this.f1465f, new ViewGroup.LayoutParams(-2, -1));
            if (this.f1465f.getAdapter() == null) {
                this.f1465f.setAdapter(new cr());
            }
            if (this.f1460a != null) {
                removeCallbacks(this.f1460a);
                this.f1460a = null;
            }
            this.f1465f.setSelection(this.f1468i);
        }
    }

    private boolean m2664c() {
        if (m2662a()) {
            removeView(this.f1465f);
            addView(this.f1464e, new ViewGroup.LayoutParams(-2, -1));
            setTabSelected(this.f1465f.getSelectedItemPosition());
        }
        return false;
    }

    private Spinner m2665d() {
        Spinner bgVar = new bg(getContext(), null, C0233b.actionDropDownStyle);
        bgVar.setLayoutParams(new bx(-2, -1));
        bgVar.setOnItemSelectedListener(this);
        return bgVar;
    }

    public void m2666a(int i) {
        View childAt = this.f1464e.getChildAt(i);
        if (this.f1460a != null) {
            removeCallbacks(this.f1460a);
        }
        this.f1460a = new cq(this, childAt);
        post(this.f1460a);
    }

    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (this.f1460a != null) {
            post(this.f1460a);
        }
    }

    protected void onConfigurationChanged(Configuration configuration) {
        if (VERSION.SDK_INT >= 8) {
            super.onConfigurationChanged(configuration);
        }
        C0247a a = C0247a.m1987a(getContext());
        setContentHeight(a.m1992e());
        this.f1462c = a.m1994g();
    }

    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.f1460a != null) {
            removeCallbacks(this.f1460a);
        }
    }

    public void onItemSelected(AdapterView adapterView, View view, int i, long j) {
        ((ct) view).m2669b().m1915d();
    }

    public void onMeasure(int i, int i2) {
        int i3 = 1;
        int mode = MeasureSpec.getMode(i);
        boolean z = mode == 1073741824;
        setFillViewport(z);
        int childCount = this.f1464e.getChildCount();
        if (childCount <= 1 || !(mode == 1073741824 || mode == Integer.MIN_VALUE)) {
            this.f1461b = -1;
        } else {
            if (childCount > 2) {
                this.f1461b = (int) (((float) MeasureSpec.getSize(i)) * 0.4f);
            } else {
                this.f1461b = MeasureSpec.getSize(i) / 2;
            }
            this.f1461b = Math.min(this.f1461b, this.f1462c);
        }
        mode = MeasureSpec.makeMeasureSpec(this.f1467h, 1073741824);
        if (z || !this.f1466g) {
            i3 = 0;
        }
        if (i3 != 0) {
            this.f1464e.measure(0, mode);
            if (this.f1464e.getMeasuredWidth() > MeasureSpec.getSize(i)) {
                m2663b();
            } else {
                m2664c();
            }
        } else {
            m2664c();
        }
        i3 = getMeasuredWidth();
        super.onMeasure(i, mode);
        int measuredWidth = getMeasuredWidth();
        if (z && i3 != measuredWidth) {
            setTabSelected(this.f1468i);
        }
    }

    public void onNothingSelected(AdapterView adapterView) {
    }

    public void setAllowCollapse(boolean z) {
        this.f1466g = z;
    }

    public void setContentHeight(int i) {
        this.f1467h = i;
        requestLayout();
    }

    public void setTabSelected(int i) {
        this.f1468i = i;
        int childCount = this.f1464e.getChildCount();
        int i2 = 0;
        while (i2 < childCount) {
            View childAt = this.f1464e.getChildAt(i2);
            boolean z = i2 == i;
            childAt.setSelected(z);
            if (z) {
                m2666a(i);
            }
            i2++;
        }
        if (this.f1465f != null && i >= 0) {
            this.f1465f.setSelection(i);
        }
    }
}
