package android.support.v7.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewParent;
import java.lang.ref.WeakReference;

public final class ViewStubCompat extends View {
    private int f1266a;
    private int f1267b;
    private WeakReference f1268c;
    private LayoutInflater f1269d;
    private dt f1270e;

    public ViewStubCompat(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ViewStubCompat(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f1266a = 0;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.ViewStubCompat, i, 0);
        this.f1267b = obtainStyledAttributes.getResourceId(C0243l.ViewStubCompat_android_inflatedId, -1);
        this.f1266a = obtainStyledAttributes.getResourceId(C0243l.ViewStubCompat_android_layout, 0);
        setId(obtainStyledAttributes.getResourceId(C0243l.ViewStubCompat_android_id, -1));
        obtainStyledAttributes.recycle();
        setVisibility(8);
        setWillNotDraw(true);
    }

    public View m2457a() {
        ViewParent parent = getParent();
        if (parent == null || !(parent instanceof ViewGroup)) {
            throw new IllegalStateException("ViewStub must have a non-null ViewGroup viewParent");
        } else if (this.f1266a != 0) {
            ViewGroup viewGroup = (ViewGroup) parent;
            View inflate = (this.f1269d != null ? this.f1269d : LayoutInflater.from(getContext())).inflate(this.f1266a, viewGroup, false);
            if (this.f1267b != -1) {
                inflate.setId(this.f1267b);
            }
            int indexOfChild = viewGroup.indexOfChild(this);
            viewGroup.removeViewInLayout(this);
            LayoutParams layoutParams = getLayoutParams();
            if (layoutParams != null) {
                viewGroup.addView(inflate, indexOfChild, layoutParams);
            } else {
                viewGroup.addView(inflate, indexOfChild);
            }
            this.f1268c = new WeakReference(inflate);
            if (this.f1270e != null) {
                this.f1270e.m2791a(this, inflate);
            }
            return inflate;
        } else {
            throw new IllegalArgumentException("ViewStub must have a valid layoutResource");
        }
    }

    protected void dispatchDraw(Canvas canvas) {
    }

    public void draw(Canvas canvas) {
    }

    public int getInflatedId() {
        return this.f1267b;
    }

    public LayoutInflater getLayoutInflater() {
        return this.f1269d;
    }

    public int getLayoutResource() {
        return this.f1266a;
    }

    protected void onMeasure(int i, int i2) {
        setMeasuredDimension(0, 0);
    }

    public void setInflatedId(int i) {
        this.f1267b = i;
    }

    public void setLayoutInflater(LayoutInflater layoutInflater) {
        this.f1269d = layoutInflater;
    }

    public void setLayoutResource(int i) {
        this.f1266a = i;
    }

    public void setOnInflateListener(dt dtVar) {
        this.f1270e = dtVar;
    }

    public void setVisibility(int i) {
        if (this.f1268c != null) {
            View view = (View) this.f1268c.get();
            if (view != null) {
                view.setVisibility(i);
                return;
            }
            throw new IllegalStateException("setVisibility called on un-referenced view");
        }
        super.setVisibility(i);
        if (i == 0 || i == 4) {
            m2457a();
        }
    }
}
