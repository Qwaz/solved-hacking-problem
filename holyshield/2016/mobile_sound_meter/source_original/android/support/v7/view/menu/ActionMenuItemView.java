package android.support.v7.view.menu;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v4.p004h.bu;
import android.support.v7.p015b.C0234c;
import android.support.v7.p015b.C0243l;
import android.support.v7.widget.C0258u;
import android.support.v7.widget.bp;
import android.support.v7.widget.cd;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.View.OnClickListener;
import android.view.View.OnLongClickListener;
import android.widget.Toast;

public class ActionMenuItemView extends bp implements aa, C0258u, OnClickListener, OnLongClickListener {
    private C0272m f911a;
    private CharSequence f912b;
    private Drawable f913c;
    private C0259k f914d;
    private cd f915e;
    private C0266c f916f;
    private boolean f917g;
    private boolean f918h;
    private int f919i;
    private int f920j;
    private int f921k;

    public ActionMenuItemView(Context context) {
        this(context, null);
    }

    public ActionMenuItemView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ActionMenuItemView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        Resources resources = context.getResources();
        this.f917g = resources.getBoolean(C0234c.abc_config_allowActionMenuItemTextWithIcon);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.ActionMenuItemView, i, 0);
        this.f919i = obtainStyledAttributes.getDimensionPixelSize(C0243l.ActionMenuItemView_android_minWidth, 0);
        obtainStyledAttributes.recycle();
        this.f921k = (int) ((resources.getDisplayMetrics().density * 32.0f) + 0.5f);
        setOnClickListener(this);
        setOnLongClickListener(this);
        this.f920j = -1;
    }

    private void m2062e() {
        int i = 0;
        int i2 = !TextUtils.isEmpty(this.f912b) ? 1 : 0;
        if (this.f913c == null || (this.f911a.m2237m() && (this.f917g || this.f918h))) {
            i = 1;
        }
        setText((i2 & i) != 0 ? this.f912b : null);
    }

    public void m2063a(C0272m c0272m, int i) {
        this.f911a = c0272m;
        setIcon(c0272m.getIcon());
        setTitle(c0272m.m2217a((aa) this));
        setId(c0272m.getItemId());
        setVisibility(c0272m.isVisible() ? 0 : 8);
        setEnabled(c0272m.isEnabled());
        if (c0272m.hasSubMenu() && this.f915e == null) {
            this.f915e = new C0265b(this);
        }
    }

    public boolean m2064a() {
        return true;
    }

    public boolean m2065b() {
        return !TextUtils.isEmpty(getText());
    }

    public boolean m2066c() {
        return m2065b() && this.f911a.getIcon() == null;
    }

    public boolean m2067d() {
        return m2065b();
    }

    public C0272m getItemData() {
        return this.f911a;
    }

    public void onClick(View view) {
        if (this.f914d != null) {
            this.f914d.m2068a(this.f911a);
        }
    }

    public void onConfigurationChanged(Configuration configuration) {
        if (VERSION.SDK_INT >= 8) {
            super.onConfigurationChanged(configuration);
        }
        this.f917g = getContext().getResources().getBoolean(C0234c.abc_config_allowActionMenuItemTextWithIcon);
        m2062e();
    }

    public boolean onLongClick(View view) {
        if (m2065b()) {
            return false;
        }
        int[] iArr = new int[2];
        Rect rect = new Rect();
        getLocationOnScreen(iArr);
        getWindowVisibleDisplayFrame(rect);
        Context context = getContext();
        int width = getWidth();
        int height = getHeight();
        int i = iArr[1] + (height / 2);
        width = (width / 2) + iArr[0];
        if (bu.m995d(view) == 0) {
            width = context.getResources().getDisplayMetrics().widthPixels - width;
        }
        Toast makeText = Toast.makeText(context, this.f911a.getTitle(), 0);
        if (i < rect.height()) {
            makeText.setGravity(8388661, width, (iArr[1] + height) - rect.top);
        } else {
            makeText.setGravity(81, 0, height);
        }
        makeText.show();
        return true;
    }

    protected void onMeasure(int i, int i2) {
        boolean b = m2065b();
        if (b && this.f920j >= 0) {
            super.setPadding(this.f920j, getPaddingTop(), getPaddingRight(), getPaddingBottom());
        }
        super.onMeasure(i, i2);
        int mode = MeasureSpec.getMode(i);
        int size = MeasureSpec.getSize(i);
        int measuredWidth = getMeasuredWidth();
        size = mode == Integer.MIN_VALUE ? Math.min(size, this.f919i) : this.f919i;
        if (mode != 1073741824 && this.f919i > 0 && measuredWidth < size) {
            super.onMeasure(MeasureSpec.makeMeasureSpec(size, 1073741824), i2);
        }
        if (!b && this.f913c != null) {
            super.setPadding((getMeasuredWidth() - this.f913c.getBounds().width()) / 2, getPaddingTop(), getPaddingRight(), getPaddingBottom());
        }
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        return (this.f911a.hasSubMenu() && this.f915e != null && this.f915e.onTouch(this, motionEvent)) ? true : super.onTouchEvent(motionEvent);
    }

    public void setCheckable(boolean z) {
    }

    public void setChecked(boolean z) {
    }

    public void setExpandedFormat(boolean z) {
        if (this.f918h != z) {
            this.f918h = z;
            if (this.f911a != null) {
                this.f911a.m2232h();
            }
        }
    }

    public void setIcon(Drawable drawable) {
        this.f913c = drawable;
        if (drawable != null) {
            float f;
            int intrinsicWidth = drawable.getIntrinsicWidth();
            int intrinsicHeight = drawable.getIntrinsicHeight();
            if (intrinsicWidth > this.f921k) {
                f = ((float) this.f921k) / ((float) intrinsicWidth);
                intrinsicWidth = this.f921k;
                intrinsicHeight = (int) (((float) intrinsicHeight) * f);
            }
            if (intrinsicHeight > this.f921k) {
                f = ((float) this.f921k) / ((float) intrinsicHeight);
                intrinsicHeight = this.f921k;
                intrinsicWidth = (int) (((float) intrinsicWidth) * f);
            }
            drawable.setBounds(0, 0, intrinsicWidth, intrinsicHeight);
        }
        setCompoundDrawables(drawable, null, null, null);
        m2062e();
    }

    public void setItemInvoker(C0259k c0259k) {
        this.f914d = c0259k;
    }

    public void setPadding(int i, int i2, int i3, int i4) {
        this.f920j = i;
        super.setPadding(i, i2, i3, i4);
    }

    public void setPopupCallback(C0266c c0266c) {
        this.f916f = c0266c;
    }

    public void setTitle(CharSequence charSequence) {
        this.f912b = charSequence;
        setContentDescription(this.f912b);
        m2062e();
    }
}
