package android.support.v7.widget;

import android.content.Context;
import android.os.Build.VERSION;
import android.support.v4.p004h.az;
import android.support.v4.p004h.dh;
import android.support.v4.widget.C0199z;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0243l;
import android.view.MotionEvent;
import android.view.View;

class cc extends cl {
    private boolean f1437g;
    private boolean f1438h;
    private boolean f1439i;
    private dh f1440j;
    private C0199z f1441k;

    public cc(Context context, boolean z) {
        super(context, null, C0233b.dropDownListViewStyle);
        this.f1438h = z;
        setCacheColorHint(0);
    }

    private void m2645a(View view, int i) {
        performItemClick(view, i, getItemIdAtPosition(i));
    }

    private void m2646a(View view, int i, float f, float f2) {
        this.f1439i = true;
        if (VERSION.SDK_INT >= 21) {
            drawableHotspotChanged(f, f2);
        }
        if (!isPressed()) {
            setPressed(true);
        }
        layoutChildren();
        if (this.f != -1) {
            View childAt = getChildAt(this.f - getFirstVisiblePosition());
            if (!(childAt == null || childAt == view || !childAt.isPressed())) {
                childAt.setPressed(false);
            }
        }
        this.f = i;
        float left = f - ((float) view.getLeft());
        float top = f2 - ((float) view.getTop());
        if (VERSION.SDK_INT >= 21) {
            view.drawableHotspotChanged(left, top);
        }
        if (!view.isPressed()) {
            view.setPressed(true);
        }
        m2639a(i, view, f, f2);
        setSelectorEnabled(false);
        refreshDrawableState();
    }

    private void m2648d() {
        this.f1439i = false;
        setPressed(false);
        drawableStateChanged();
        View childAt = getChildAt(this.f - getFirstVisiblePosition());
        if (childAt != null) {
            childAt.setPressed(false);
        }
        if (this.f1440j != null) {
            this.f1440j.m1232b();
            this.f1440j = null;
        }
    }

    protected boolean m2649a() {
        return this.f1439i || super.m2641a();
    }

    public boolean m2650a(MotionEvent motionEvent, int i) {
        boolean z;
        boolean z2;
        int a = az.m895a(motionEvent);
        switch (a) {
            case C0243l.View_android_focusable /*1*/:
                z = false;
                break;
            case C0243l.View_paddingStart /*2*/:
                z = true;
                break;
            case C0243l.View_paddingEnd /*3*/:
                z = false;
                z2 = false;
                break;
            default:
                z = false;
                z2 = true;
                break;
        }
        int findPointerIndex = motionEvent.findPointerIndex(i);
        if (findPointerIndex < 0) {
            z = false;
            z2 = false;
        } else {
            int x = (int) motionEvent.getX(findPointerIndex);
            findPointerIndex = (int) motionEvent.getY(findPointerIndex);
            int pointToPosition = pointToPosition(x, findPointerIndex);
            if (pointToPosition == -1) {
                z2 = z;
                z = true;
            } else {
                View childAt = getChildAt(pointToPosition - getFirstVisiblePosition());
                m2646a(childAt, pointToPosition, (float) x, (float) findPointerIndex);
                if (a == 1) {
                    m2645a(childAt, pointToPosition);
                }
                z = false;
                z2 = true;
            }
        }
        if (!z2 || r0) {
            m2648d();
        }
        if (z2) {
            if (this.f1441k == null) {
                this.f1441k = new C0199z(this);
            }
            this.f1441k.m1412a(true);
            this.f1441k.onTouch(this, motionEvent);
        } else if (this.f1441k != null) {
            this.f1441k.m1412a(false);
        }
        return z2;
    }

    public boolean hasFocus() {
        return this.f1438h || super.hasFocus();
    }

    public boolean hasWindowFocus() {
        return this.f1438h || super.hasWindowFocus();
    }

    public boolean isFocused() {
        return this.f1438h || super.isFocused();
    }

    public boolean isInTouchMode() {
        return (this.f1438h && this.f1437g) || super.isInTouchMode();
    }
}
