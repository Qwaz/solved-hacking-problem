package android.support.v7.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.support.v4.p006c.p007a.C0062a;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup.LayoutParams;
import android.widget.AbsListView;
import android.widget.ListAdapter;
import android.widget.ListView;
import java.lang.reflect.Field;

public class cl extends ListView {
    private static final int[] f1428g;
    final Rect f1429a;
    int f1430b;
    int f1431c;
    int f1432d;
    int f1433e;
    protected int f1434f;
    private Field f1435h;
    private cm f1436i;

    static {
        f1428g = new int[]{0};
    }

    public cl(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f1429a = new Rect();
        this.f1430b = 0;
        this.f1431c = 0;
        this.f1432d = 0;
        this.f1433e = 0;
        try {
            this.f1435h = AbsListView.class.getDeclaredField("mIsChildViewEnabled");
            this.f1435h.setAccessible(true);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
    }

    public int m2637a(int i, int i2, int i3, int i4, int i5) {
        int listPaddingTop = getListPaddingTop();
        int listPaddingBottom = getListPaddingBottom();
        getListPaddingLeft();
        getListPaddingRight();
        int dividerHeight = getDividerHeight();
        Drawable divider = getDivider();
        ListAdapter adapter = getAdapter();
        if (adapter == null) {
            return listPaddingTop + listPaddingBottom;
        }
        listPaddingBottom += listPaddingTop;
        if (dividerHeight <= 0 || divider == null) {
            dividerHeight = 0;
        }
        int i6 = 0;
        View view = null;
        int i7 = 0;
        int count = adapter.getCount();
        int i8 = 0;
        while (i8 < count) {
            View view2;
            listPaddingTop = adapter.getItemViewType(i8);
            if (listPaddingTop != i7) {
                int i9 = listPaddingTop;
                view2 = null;
                i7 = i9;
            } else {
                view2 = view;
            }
            view = adapter.getView(i8, view2, this);
            LayoutParams layoutParams = view.getLayoutParams();
            if (layoutParams == null) {
                layoutParams = generateDefaultLayoutParams();
                view.setLayoutParams(layoutParams);
            }
            view.measure(i, layoutParams.height > 0 ? MeasureSpec.makeMeasureSpec(layoutParams.height, 1073741824) : MeasureSpec.makeMeasureSpec(0, 0));
            view.forceLayout();
            listPaddingTop = (i8 > 0 ? listPaddingBottom + dividerHeight : listPaddingBottom) + view.getMeasuredHeight();
            if (listPaddingTop >= i4) {
                return (i5 < 0 || i8 <= i5 || i6 <= 0 || listPaddingTop == i4) ? i4 : i6;
            } else {
                if (i5 >= 0 && i8 >= i5) {
                    i6 = listPaddingTop;
                }
                i8++;
                listPaddingBottom = listPaddingTop;
            }
        }
        return listPaddingBottom;
    }

    protected void m2638a(int i, View view) {
        boolean z = true;
        Drawable selector = getSelector();
        boolean z2 = (selector == null || i == -1) ? false : true;
        if (z2) {
            selector.setVisible(false, false);
        }
        m2643b(i, view);
        if (z2) {
            Rect rect = this.f1429a;
            float exactCenterX = rect.exactCenterX();
            float exactCenterY = rect.exactCenterY();
            if (getVisibility() != 0) {
                z = false;
            }
            selector.setVisible(z, false);
            C0062a.m455a(selector, exactCenterX, exactCenterY);
        }
    }

    protected void m2639a(int i, View view, float f, float f2) {
        m2638a(i, view);
        Drawable selector = getSelector();
        if (selector != null && i != -1) {
            C0062a.m455a(selector, f, f2);
        }
    }

    protected void m2640a(Canvas canvas) {
        if (!this.f1429a.isEmpty()) {
            Drawable selector = getSelector();
            if (selector != null) {
                selector.setBounds(this.f1429a);
                selector.draw(canvas);
            }
        }
    }

    protected boolean m2641a() {
        return false;
    }

    protected void m2642b() {
        Drawable selector = getSelector();
        if (selector != null && m2644c()) {
            selector.setState(getDrawableState());
        }
    }

    protected void m2643b(int i, View view) {
        Rect rect = this.f1429a;
        rect.set(view.getLeft(), view.getTop(), view.getRight(), view.getBottom());
        rect.left -= this.f1430b;
        rect.top -= this.f1431c;
        rect.right += this.f1432d;
        rect.bottom += this.f1433e;
        try {
            boolean z = this.f1435h.getBoolean(this);
            if (view.isEnabled() != z) {
                this.f1435h.set(this, Boolean.valueOf(!z));
                if (i != -1) {
                    refreshDrawableState();
                }
            }
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
    }

    protected boolean m2644c() {
        return m2641a() && isPressed();
    }

    protected void dispatchDraw(Canvas canvas) {
        m2640a(canvas);
        super.dispatchDraw(canvas);
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        setSelectorEnabled(true);
        m2642b();
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        switch (motionEvent.getAction()) {
            case C0243l.View_android_theme /*0*/:
                this.f1434f = pointToPosition((int) motionEvent.getX(), (int) motionEvent.getY());
                break;
        }
        return super.onTouchEvent(motionEvent);
    }

    public void setSelector(Drawable drawable) {
        this.f1436i = drawable != null ? new cm(drawable) : null;
        super.setSelector(this.f1436i);
        Rect rect = new Rect();
        if (drawable != null) {
            drawable.getPadding(rect);
        }
        this.f1430b = rect.left;
        this.f1431c = rect.top;
        this.f1432d = rect.right;
        this.f1433e = rect.bottom;
    }

    protected void setSelectorEnabled(boolean z) {
        if (this.f1436i != null) {
            this.f1436i.m2651a(z);
        }
    }
}
