package android.support.v7.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.ActionMode.Callback;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.FrameLayout.LayoutParams;

public class ActionBarContainer extends FrameLayout {
    Drawable f1076a;
    Drawable f1077b;
    Drawable f1078c;
    boolean f1079d;
    boolean f1080e;
    private boolean f1081f;
    private View f1082g;
    private View f1083h;
    private View f1084i;
    private int f1085j;

    public ActionBarContainer(Context context) {
        this(context, null);
    }

    public ActionBarContainer(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        setBackgroundDrawable(VERSION.SDK_INT >= 21 ? new C0286d(this) : new C0285c(this));
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.ActionBar);
        this.f1076a = obtainStyledAttributes.getDrawable(C0243l.ActionBar_background);
        this.f1077b = obtainStyledAttributes.getDrawable(C0243l.ActionBar_backgroundStacked);
        this.f1085j = obtainStyledAttributes.getDimensionPixelSize(C0243l.ActionBar_height, -1);
        if (getId() == C0238g.split_action_bar) {
            this.f1079d = true;
            this.f1078c = obtainStyledAttributes.getDrawable(C0243l.ActionBar_backgroundSplit);
        }
        obtainStyledAttributes.recycle();
        boolean z = this.f1079d ? this.f1078c == null : this.f1076a == null && this.f1077b == null;
        setWillNotDraw(z);
    }

    private boolean m2279a(View view) {
        return view == null || view.getVisibility() == 8 || view.getMeasuredHeight() == 0;
    }

    private int m2280b(View view) {
        LayoutParams layoutParams = (LayoutParams) view.getLayoutParams();
        return layoutParams.bottomMargin + (view.getMeasuredHeight() + layoutParams.topMargin);
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1076a != null && this.f1076a.isStateful()) {
            this.f1076a.setState(getDrawableState());
        }
        if (this.f1077b != null && this.f1077b.isStateful()) {
            this.f1077b.setState(getDrawableState());
        }
        if (this.f1078c != null && this.f1078c.isStateful()) {
            this.f1078c.setState(getDrawableState());
        }
    }

    public View getTabContainer() {
        return this.f1082g;
    }

    public void jumpDrawablesToCurrentState() {
        if (VERSION.SDK_INT >= 11) {
            super.jumpDrawablesToCurrentState();
            if (this.f1076a != null) {
                this.f1076a.jumpToCurrentState();
            }
            if (this.f1077b != null) {
                this.f1077b.jumpToCurrentState();
            }
            if (this.f1078c != null) {
                this.f1078c.jumpToCurrentState();
            }
        }
    }

    public void onFinishInflate() {
        super.onFinishInflate();
        this.f1083h = findViewById(C0238g.action_bar);
        this.f1084i = findViewById(C0238g.action_context_bar);
    }

    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        return this.f1081f || super.onInterceptTouchEvent(motionEvent);
    }

    public void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int i5 = 1;
        super.onLayout(z, i, i2, i3, i4);
        View view = this.f1082g;
        boolean z2 = (view == null || view.getVisibility() == 8) ? false : true;
        if (!(view == null || view.getVisibility() == 8)) {
            int measuredHeight = getMeasuredHeight();
            LayoutParams layoutParams = (LayoutParams) view.getLayoutParams();
            view.layout(i, (measuredHeight - view.getMeasuredHeight()) - layoutParams.bottomMargin, i3, measuredHeight - layoutParams.bottomMargin);
        }
        if (!this.f1079d) {
            int i6;
            if (this.f1076a != null) {
                if (this.f1083h.getVisibility() == 0) {
                    this.f1076a.setBounds(this.f1083h.getLeft(), this.f1083h.getTop(), this.f1083h.getRight(), this.f1083h.getBottom());
                } else if (this.f1084i == null || this.f1084i.getVisibility() != 0) {
                    this.f1076a.setBounds(0, 0, 0, 0);
                } else {
                    this.f1076a.setBounds(this.f1084i.getLeft(), this.f1084i.getTop(), this.f1084i.getRight(), this.f1084i.getBottom());
                }
                i6 = 1;
            } else {
                i6 = 0;
            }
            this.f1080e = z2;
            if (!z2 || this.f1077b == null) {
                i5 = i6;
            } else {
                this.f1077b.setBounds(view.getLeft(), view.getTop(), view.getRight(), view.getBottom());
            }
        } else if (this.f1078c != null) {
            this.f1078c.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
        } else {
            i5 = 0;
        }
        if (i5 != 0) {
            invalidate();
        }
    }

    public void onMeasure(int i, int i2) {
        if (this.f1083h == null && MeasureSpec.getMode(i2) == Integer.MIN_VALUE && this.f1085j >= 0) {
            i2 = MeasureSpec.makeMeasureSpec(Math.min(this.f1085j, MeasureSpec.getSize(i2)), Integer.MIN_VALUE);
        }
        super.onMeasure(i, i2);
        if (this.f1083h != null) {
            int mode = MeasureSpec.getMode(i2);
            if (this.f1082g != null && this.f1082g.getVisibility() != 8 && mode != 1073741824) {
                int b = !m2279a(this.f1083h) ? m2280b(this.f1083h) : !m2279a(this.f1084i) ? m2280b(this.f1084i) : 0;
                setMeasuredDimension(getMeasuredWidth(), Math.min(b + m2280b(this.f1082g), mode == Integer.MIN_VALUE ? MeasureSpec.getSize(i2) : Integer.MAX_VALUE));
            }
        }
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        super.onTouchEvent(motionEvent);
        return true;
    }

    public void setPrimaryBackground(Drawable drawable) {
        boolean z = true;
        if (this.f1076a != null) {
            this.f1076a.setCallback(null);
            unscheduleDrawable(this.f1076a);
        }
        this.f1076a = drawable;
        if (drawable != null) {
            drawable.setCallback(this);
            if (this.f1083h != null) {
                this.f1076a.setBounds(this.f1083h.getLeft(), this.f1083h.getTop(), this.f1083h.getRight(), this.f1083h.getBottom());
            }
        }
        if (this.f1079d) {
            if (this.f1078c != null) {
                z = false;
            }
        } else if (!(this.f1076a == null && this.f1077b == null)) {
            z = false;
        }
        setWillNotDraw(z);
        invalidate();
    }

    public void setSplitBackground(Drawable drawable) {
        boolean z = true;
        if (this.f1078c != null) {
            this.f1078c.setCallback(null);
            unscheduleDrawable(this.f1078c);
        }
        this.f1078c = drawable;
        if (drawable != null) {
            drawable.setCallback(this);
            if (this.f1079d && this.f1078c != null) {
                this.f1078c.setBounds(0, 0, getMeasuredWidth(), getMeasuredHeight());
            }
        }
        if (this.f1079d) {
            if (this.f1078c != null) {
                z = false;
            }
        } else if (!(this.f1076a == null && this.f1077b == null)) {
            z = false;
        }
        setWillNotDraw(z);
        invalidate();
    }

    public void setStackedBackground(Drawable drawable) {
        boolean z = true;
        if (this.f1077b != null) {
            this.f1077b.setCallback(null);
            unscheduleDrawable(this.f1077b);
        }
        this.f1077b = drawable;
        if (drawable != null) {
            drawable.setCallback(this);
            if (this.f1080e && this.f1077b != null) {
                this.f1077b.setBounds(this.f1082g.getLeft(), this.f1082g.getTop(), this.f1082g.getRight(), this.f1082g.getBottom());
            }
        }
        if (this.f1079d) {
            if (this.f1078c != null) {
                z = false;
            }
        } else if (!(this.f1076a == null && this.f1077b == null)) {
            z = false;
        }
        setWillNotDraw(z);
        invalidate();
    }

    public void setTabContainer(cp cpVar) {
        if (this.f1082g != null) {
            removeView(this.f1082g);
        }
        this.f1082g = cpVar;
        if (cpVar != null) {
            addView(cpVar);
            ViewGroup.LayoutParams layoutParams = cpVar.getLayoutParams();
            layoutParams.width = -1;
            layoutParams.height = -2;
            cpVar.setAllowCollapse(false);
        }
    }

    public void setTransitioning(boolean z) {
        this.f1081f = z;
        setDescendantFocusability(z ? 393216 : 262144);
    }

    public void setVisibility(int i) {
        super.setVisibility(i);
        boolean z = i == 0;
        if (this.f1076a != null) {
            this.f1076a.setVisible(z, false);
        }
        if (this.f1077b != null) {
            this.f1077b.setVisible(z, false);
        }
        if (this.f1078c != null) {
            this.f1078c.setVisible(z, false);
        }
    }

    public ActionMode startActionModeForChild(View view, Callback callback) {
        return null;
    }

    protected boolean verifyDrawable(Drawable drawable) {
        return (drawable == this.f1076a && !this.f1079d) || ((drawable == this.f1077b && this.f1080e) || ((drawable == this.f1078c && this.f1079d) || super.verifyDrawable(drawable)));
    }
}
