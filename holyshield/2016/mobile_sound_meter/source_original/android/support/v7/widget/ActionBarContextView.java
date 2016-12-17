package android.support.v7.widget;

import android.content.Context;
import android.os.Build.VERSION;
import android.support.v4.p004h.dh;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0240i;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0212b;
import android.support.v7.view.menu.C0264i;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.accessibility.AccessibilityEvent;
import android.widget.LinearLayout;
import android.widget.TextView;

public class ActionBarContextView extends C0283a {
    private CharSequence f1094g;
    private CharSequence f1095h;
    private View f1096i;
    private View f1097j;
    private LinearLayout f1098k;
    private TextView f1099l;
    private TextView f1100m;
    private int f1101n;
    private int f1102o;
    private boolean f1103p;
    private int f1104q;

    public ActionBarContextView(Context context) {
        this(context, null);
    }

    public ActionBarContextView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.actionModeStyle);
    }

    public ActionBarContextView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        dh a = dh.m2710a(context, attributeSet, C0243l.ActionMode, i, 0);
        setBackgroundDrawable(a.m2713a(C0243l.ActionMode_background));
        this.f1101n = a.m2726g(C0243l.ActionMode_titleTextStyle, 0);
        this.f1102o = a.m2726g(C0243l.ActionMode_subtitleTextStyle, 0);
        this.e = a.m2724f(C0243l.ActionMode_height, 0);
        this.f1104q = a.m2726g(C0243l.ActionMode_closeItemLayout, C0240i.abc_action_mode_close_item_material);
        a.m2714a();
    }

    private void m2288e() {
        int i = 8;
        Object obj = 1;
        if (this.f1098k == null) {
            LayoutInflater.from(getContext()).inflate(C0240i.abc_action_bar_title_item, this);
            this.f1098k = (LinearLayout) getChildAt(getChildCount() - 1);
            this.f1099l = (TextView) this.f1098k.findViewById(C0238g.action_bar_title);
            this.f1100m = (TextView) this.f1098k.findViewById(C0238g.action_bar_subtitle);
            if (this.f1101n != 0) {
                this.f1099l.setTextAppearance(getContext(), this.f1101n);
            }
            if (this.f1102o != 0) {
                this.f1100m.setTextAppearance(getContext(), this.f1102o);
            }
        }
        this.f1099l.setText(this.f1094g);
        this.f1100m.setText(this.f1095h);
        Object obj2 = !TextUtils.isEmpty(this.f1094g) ? 1 : null;
        if (TextUtils.isEmpty(this.f1095h)) {
            obj = null;
        }
        this.f1100m.setVisibility(obj != null ? 0 : 8);
        LinearLayout linearLayout = this.f1098k;
        if (!(obj2 == null && obj == null)) {
            i = 0;
        }
        linearLayout.setVisibility(i);
        if (this.f1098k.getParent() == null) {
            addView(this.f1098k);
        }
    }

    public /* bridge */ /* synthetic */ dh m2289a(int i, long j) {
        return super.m2286a(i, j);
    }

    public void m2290a(C0212b c0212b) {
        if (this.f1096i == null) {
            this.f1096i = LayoutInflater.from(getContext()).inflate(this.f1104q, this, false);
            addView(this.f1096i);
        } else if (this.f1096i.getParent() == null) {
            addView(this.f1096i);
        }
        this.f1096i.findViewById(C0238g.action_mode_close_button).setOnClickListener(new C0289e(this, c0212b));
        C0264i c0264i = (C0264i) c0212b.m1883b();
        if (this.d != null) {
            this.d.m2830f();
        }
        this.d = new C0294k(getContext());
        this.d.m2826c(true);
        LayoutParams layoutParams = new LayoutParams(-2, -1);
        c0264i.m2112a(this.d, this.b);
        this.c = (ActionMenuView) this.d.m2811a((ViewGroup) this);
        this.c.setBackgroundDrawable(null);
        addView(this.c, layoutParams);
    }

    public boolean m2291a() {
        return this.d != null ? this.d.m2828d() : false;
    }

    public void m2292b() {
        if (this.f1096i == null) {
            m2293c();
        }
    }

    public void m2293c() {
        removeAllViews();
        this.f1097j = null;
        this.c = null;
    }

    public boolean m2294d() {
        return this.f1103p;
    }

    protected LayoutParams generateDefaultLayoutParams() {
        return new MarginLayoutParams(-1, -2);
    }

    public LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new MarginLayoutParams(getContext(), attributeSet);
    }

    public /* bridge */ /* synthetic */ int getAnimatedVisibility() {
        return super.getAnimatedVisibility();
    }

    public /* bridge */ /* synthetic */ int getContentHeight() {
        return super.getContentHeight();
    }

    public CharSequence getSubtitle() {
        return this.f1095h;
    }

    public CharSequence getTitle() {
        return this.f1094g;
    }

    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.d != null) {
            this.d.m2829e();
            this.d.m2831g();
        }
    }

    public /* bridge */ /* synthetic */ boolean onHoverEvent(MotionEvent motionEvent) {
        return super.onHoverEvent(motionEvent);
    }

    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        if (VERSION.SDK_INT < 14) {
            return;
        }
        if (accessibilityEvent.getEventType() == 32) {
            accessibilityEvent.setSource(this);
            accessibilityEvent.setClassName(getClass().getName());
            accessibilityEvent.setPackageName(getContext().getPackageName());
            accessibilityEvent.setContentDescription(this.f1094g);
            return;
        }
        super.onInitializeAccessibilityEvent(accessibilityEvent);
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int i5;
        boolean a = du.m2794a(this);
        int paddingRight = a ? (i3 - i) - getPaddingRight() : getPaddingLeft();
        int paddingTop = getPaddingTop();
        int paddingTop2 = ((i4 - i2) - getPaddingTop()) - getPaddingBottom();
        if (this.f1096i == null || this.f1096i.getVisibility() == 8) {
            i5 = paddingRight;
        } else {
            MarginLayoutParams marginLayoutParams = (MarginLayoutParams) this.f1096i.getLayoutParams();
            i5 = a ? marginLayoutParams.rightMargin : marginLayoutParams.leftMargin;
            int i6 = a ? marginLayoutParams.leftMargin : marginLayoutParams.rightMargin;
            i5 = C0283a.m2281a(paddingRight, i5, a);
            i5 = C0283a.m2281a(m2285a(this.f1096i, i5, paddingTop, paddingTop2, a) + i5, i6, a);
        }
        if (!(this.f1098k == null || this.f1097j != null || this.f1098k.getVisibility() == 8)) {
            i5 += m2285a(this.f1098k, i5, paddingTop, paddingTop2, a);
        }
        if (this.f1097j != null) {
            int a2 = m2285a(this.f1097j, i5, paddingTop, paddingTop2, a) + i5;
        }
        i5 = a ? getPaddingLeft() : (i3 - i) - getPaddingRight();
        if (this.c != null) {
            a2 = m2285a(this.c, i5, paddingTop, paddingTop2, !a) + i5;
        }
    }

    protected void onMeasure(int i, int i2) {
        int i3 = 1073741824;
        int i4 = 0;
        if (MeasureSpec.getMode(i) != 1073741824) {
            throw new IllegalStateException(getClass().getSimpleName() + " can only be used " + "with android:layout_width=\"match_parent\" (or fill_parent)");
        } else if (MeasureSpec.getMode(i2) == 0) {
            throw new IllegalStateException(getClass().getSimpleName() + " can only be used " + "with android:layout_height=\"wrap_content\"");
        } else {
            int a;
            int size = MeasureSpec.getSize(i);
            int size2 = this.e > 0 ? this.e : MeasureSpec.getSize(i2);
            int paddingTop = getPaddingTop() + getPaddingBottom();
            int paddingLeft = (size - getPaddingLeft()) - getPaddingRight();
            int i5 = size2 - paddingTop;
            int makeMeasureSpec = MeasureSpec.makeMeasureSpec(i5, Integer.MIN_VALUE);
            if (this.f1096i != null) {
                a = m2284a(this.f1096i, paddingLeft, makeMeasureSpec, 0);
                MarginLayoutParams marginLayoutParams = (MarginLayoutParams) this.f1096i.getLayoutParams();
                paddingLeft = a - (marginLayoutParams.rightMargin + marginLayoutParams.leftMargin);
            }
            if (this.c != null && this.c.getParent() == this) {
                paddingLeft = m2284a(this.c, paddingLeft, makeMeasureSpec, 0);
            }
            if (this.f1098k != null && this.f1097j == null) {
                if (this.f1103p) {
                    this.f1098k.measure(MeasureSpec.makeMeasureSpec(0, 0), makeMeasureSpec);
                    a = this.f1098k.getMeasuredWidth();
                    makeMeasureSpec = a <= paddingLeft ? 1 : 0;
                    if (makeMeasureSpec != 0) {
                        paddingLeft -= a;
                    }
                    this.f1098k.setVisibility(makeMeasureSpec != 0 ? 0 : 8);
                } else {
                    paddingLeft = m2284a(this.f1098k, paddingLeft, makeMeasureSpec, 0);
                }
            }
            if (this.f1097j != null) {
                LayoutParams layoutParams = this.f1097j.getLayoutParams();
                makeMeasureSpec = layoutParams.width != -2 ? 1073741824 : Integer.MIN_VALUE;
                if (layoutParams.width >= 0) {
                    paddingLeft = Math.min(layoutParams.width, paddingLeft);
                }
                if (layoutParams.height == -2) {
                    i3 = Integer.MIN_VALUE;
                }
                this.f1097j.measure(MeasureSpec.makeMeasureSpec(paddingLeft, makeMeasureSpec), MeasureSpec.makeMeasureSpec(layoutParams.height >= 0 ? Math.min(layoutParams.height, i5) : i5, i3));
            }
            if (this.e <= 0) {
                makeMeasureSpec = getChildCount();
                size2 = 0;
                while (i4 < makeMeasureSpec) {
                    paddingLeft = getChildAt(i4).getMeasuredHeight() + paddingTop;
                    if (paddingLeft <= size2) {
                        paddingLeft = size2;
                    }
                    i4++;
                    size2 = paddingLeft;
                }
                setMeasuredDimension(size, size2);
                return;
            }
            setMeasuredDimension(size, size2);
        }
    }

    public /* bridge */ /* synthetic */ boolean onTouchEvent(MotionEvent motionEvent) {
        return super.onTouchEvent(motionEvent);
    }

    public void setContentHeight(int i) {
        this.e = i;
    }

    public void setCustomView(View view) {
        if (this.f1097j != null) {
            removeView(this.f1097j);
        }
        this.f1097j = view;
        if (!(view == null || this.f1098k == null)) {
            removeView(this.f1098k);
            this.f1098k = null;
        }
        if (view != null) {
            addView(view);
        }
        requestLayout();
    }

    public void setSubtitle(CharSequence charSequence) {
        this.f1095h = charSequence;
        m2288e();
    }

    public void setTitle(CharSequence charSequence) {
        this.f1094g = charSequence;
        m2288e();
    }

    public void setTitleOptional(boolean z) {
        if (z != this.f1103p) {
            requestLayout();
        }
        this.f1103p = z;
    }

    public /* bridge */ /* synthetic */ void setVisibility(int i) {
        super.setVisibility(i);
    }

    public boolean shouldDelayChildPressedState() {
        return false;
    }
}
