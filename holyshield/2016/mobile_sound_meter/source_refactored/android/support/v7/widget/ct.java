package android.support.v7.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v7.p014a.C0214d;
import android.support.v7.p015b.C0233b;
import android.text.TextUtils;
import android.text.TextUtils.TruncateAt;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.View.OnLongClickListener;
import android.view.ViewGroup.LayoutParams;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

class ct extends bw implements OnLongClickListener {
    final /* synthetic */ cp f1473a;
    private final int[] f1474b;
    private C0214d f1475c;
    private TextView f1476d;
    private ImageView f1477e;
    private View f1478f;

    public ct(cp cpVar, Context context, C0214d c0214d, boolean z) {
        this.f1473a = cpVar;
        super(context, null, C0233b.actionBarTabStyle);
        this.f1474b = new int[]{16842964};
        this.f1475c = c0214d;
        dh a = dh.m2710a(context, null, this.f1474b, C0233b.actionBarTabStyle, 0);
        if (a.m2725f(0)) {
            setBackgroundDrawable(a.m2713a(0));
        }
        a.m2714a();
        if (z) {
            setGravity(8388627);
        }
        m2667a();
    }

    public void m2667a() {
        C0214d c0214d = this.f1475c;
        View c = c0214d.m1914c();
        if (c != null) {
            ct parent = c.getParent();
            if (parent != this) {
                if (parent != null) {
                    parent.removeView(c);
                }
                addView(c);
            }
            this.f1478f = c;
            if (this.f1476d != null) {
                this.f1476d.setVisibility(8);
            }
            if (this.f1477e != null) {
                this.f1477e.setVisibility(8);
                this.f1477e.setImageDrawable(null);
                return;
            }
            return;
        }
        if (this.f1478f != null) {
            removeView(this.f1478f);
            this.f1478f = null;
        }
        Drawable a = c0214d.m1912a();
        CharSequence b = c0214d.m1913b();
        if (a != null) {
            if (this.f1477e == null) {
                View imageView = new ImageView(getContext());
                LayoutParams bxVar = new bx(-2, -2);
                bxVar.f1423h = 16;
                imageView.setLayoutParams(bxVar);
                addView(imageView, 0);
                this.f1477e = imageView;
            }
            this.f1477e.setImageDrawable(a);
            this.f1477e.setVisibility(0);
        } else if (this.f1477e != null) {
            this.f1477e.setVisibility(8);
            this.f1477e.setImageDrawable(null);
        }
        boolean z = !TextUtils.isEmpty(b);
        if (z) {
            if (this.f1476d == null) {
                imageView = new bp(getContext(), null, C0233b.actionBarTabTextStyle);
                imageView.setEllipsize(TruncateAt.END);
                bxVar = new bx(-2, -2);
                bxVar.f1423h = 16;
                imageView.setLayoutParams(bxVar);
                addView(imageView);
                this.f1476d = imageView;
            }
            this.f1476d.setText(b);
            this.f1476d.setVisibility(0);
        } else if (this.f1476d != null) {
            this.f1476d.setVisibility(8);
            this.f1476d.setText(null);
        }
        if (this.f1477e != null) {
            this.f1477e.setContentDescription(c0214d.m1916e());
        }
        if (z || TextUtils.isEmpty(c0214d.m1916e())) {
            setOnLongClickListener(null);
            setLongClickable(false);
            return;
        }
        setOnLongClickListener(this);
    }

    public void m2668a(C0214d c0214d) {
        this.f1475c = c0214d;
        m2667a();
    }

    public C0214d m2669b() {
        return this.f1475c;
    }

    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        accessibilityEvent.setClassName(C0214d.class.getName());
    }

    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        if (VERSION.SDK_INT >= 14) {
            accessibilityNodeInfo.setClassName(C0214d.class.getName());
        }
    }

    public boolean onLongClick(View view) {
        int[] iArr = new int[2];
        getLocationOnScreen(iArr);
        Context context = getContext();
        int width = getWidth();
        int height = getHeight();
        int i = context.getResources().getDisplayMetrics().widthPixels;
        Toast makeText = Toast.makeText(context, this.f1475c.m1916e(), 0);
        makeText.setGravity(49, (iArr[0] + (width / 2)) - (i / 2), height);
        makeText.show();
        return true;
    }

    public void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        if (this.f1473a.f1461b > 0 && getMeasuredWidth() > this.f1473a.f1461b) {
            super.onMeasure(MeasureSpec.makeMeasureSpec(this.f1473a.f1461b, 1073741824), i2);
        }
    }

    public void setSelected(boolean z) {
        Object obj = isSelected() != z ? 1 : null;
        super.setSelected(z);
        if (obj != null && z) {
            sendAccessibilityEvent(4);
        }
    }
}
