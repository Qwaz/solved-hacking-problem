package android.support.v7.widget;

import android.content.Context;
import android.database.DataSetObserver;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.C0161n;
import android.support.v7.p015b.C0241j;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.PopupWindow.OnDismissListener;

public class ActivityChooserView extends ViewGroup {
    C0161n f1161a;
    private final ag f1162b;
    private final ah f1163c;
    private final bw f1164d;
    private final FrameLayout f1165e;
    private final ImageView f1166f;
    private final FrameLayout f1167g;
    private final int f1168h;
    private final DataSetObserver f1169i;
    private final OnGlobalLayoutListener f1170j;
    private by f1171k;
    private OnDismissListener f1172l;
    private boolean f1173m;
    private int f1174n;
    private boolean f1175o;
    private int f1176p;

    public class InnerLayout extends bw {
        private static final int[] f1160a;

        static {
            f1160a = new int[]{16842964};
        }

        public InnerLayout(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            dh a = dh.m2709a(context, attributeSet, f1160a);
            setBackgroundDrawable(a.m2713a(0));
            a.m2714a();
        }
    }

    private void m2375a(int i) {
        if (this.f1162b.m2469d() == null) {
            throw new IllegalStateException("No data model. Did you call #setDataModel?");
        }
        getViewTreeObserver().addOnGlobalLayoutListener(this.f1170j);
        boolean z = this.f1167g.getVisibility() == 0;
        int c = this.f1162b.m2468c();
        int i2 = z ? 1 : 0;
        if (i == Integer.MAX_VALUE || c <= i2 + i) {
            this.f1162b.m2465a(false);
            this.f1162b.m2463a(i);
        } else {
            this.f1162b.m2465a(true);
            this.f1162b.m2463a(i - 1);
        }
        by listPopupWindow = getListPopupWindow();
        if (!listPopupWindow.m2581k()) {
            if (this.f1173m || !z) {
                this.f1162b.m2466a(true, z);
            } else {
                this.f1162b.m2466a(false, false);
            }
            listPopupWindow.m2574f(Math.min(this.f1162b.m2462a(), this.f1168h));
            listPopupWindow.m2567c();
            if (this.f1161a != null) {
                this.f1161a.m1339a(true);
            }
            listPopupWindow.m2583m().setContentDescription(getContext().getString(C0241j.abc_activitychooserview_choose_application));
        }
    }

    private by getListPopupWindow() {
        if (this.f1171k == null) {
            this.f1171k = new by(getContext());
            this.f1171k.m2563a(this.f1162b);
            this.f1171k.m2561a((View) this);
            this.f1171k.m2565a(true);
            this.f1171k.m2562a(this.f1163c);
            this.f1171k.m2564a(this.f1163c);
        }
        return this.f1171k;
    }

    public boolean m2384a() {
        if (m2386c() || !this.f1175o) {
            return false;
        }
        this.f1173m = false;
        m2375a(this.f1174n);
        return true;
    }

    public boolean m2385b() {
        if (m2386c()) {
            getListPopupWindow().m2579i();
            ViewTreeObserver viewTreeObserver = getViewTreeObserver();
            if (viewTreeObserver.isAlive()) {
                viewTreeObserver.removeGlobalOnLayoutListener(this.f1170j);
            }
        }
        return true;
    }

    public boolean m2386c() {
        return getListPopupWindow().m2581k();
    }

    public C0307z getDataModel() {
        return this.f1162b.m2469d();
    }

    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        C0307z d = this.f1162b.m2469d();
        if (d != null) {
            d.registerObserver(this.f1169i);
        }
        this.f1175o = true;
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        C0307z d = this.f1162b.m2469d();
        if (d != null) {
            d.unregisterObserver(this.f1169i);
        }
        ViewTreeObserver viewTreeObserver = getViewTreeObserver();
        if (viewTreeObserver.isAlive()) {
            viewTreeObserver.removeGlobalOnLayoutListener(this.f1170j);
        }
        if (m2386c()) {
            m2385b();
        }
        this.f1175o = false;
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        this.f1164d.layout(0, 0, i3 - i, i4 - i2);
        if (!m2386c()) {
            m2385b();
        }
    }

    protected void onMeasure(int i, int i2) {
        View view = this.f1164d;
        if (this.f1167g.getVisibility() != 0) {
            i2 = MeasureSpec.makeMeasureSpec(MeasureSpec.getSize(i2), 1073741824);
        }
        measureChild(view, i, i2);
        setMeasuredDimension(view.getMeasuredWidth(), view.getMeasuredHeight());
    }

    public void setActivityChooserModel(C0307z c0307z) {
        this.f1162b.m2464a(c0307z);
        if (m2386c()) {
            m2385b();
            m2384a();
        }
    }

    public void setDefaultActionButtonContentDescription(int i) {
        this.f1176p = i;
    }

    public void setExpandActivityOverflowButtonContentDescription(int i) {
        this.f1166f.setContentDescription(getContext().getString(i));
    }

    public void setExpandActivityOverflowButtonDrawable(Drawable drawable) {
        this.f1166f.setImageDrawable(drawable);
    }

    public void setInitialActivityCount(int i) {
        this.f1174n = i;
    }

    public void setOnDismissListener(OnDismissListener onDismissListener) {
        this.f1172l = onDismissListener;
    }

    public void setProvider(C0161n c0161n) {
        this.f1161a = c0161n;
    }
}
