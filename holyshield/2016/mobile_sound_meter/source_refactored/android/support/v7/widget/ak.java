package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bo;
import android.support.v7.p015b.C0233b;
import android.util.AttributeSet;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Button;
import android.widget.TextView;

public class ak extends Button implements bo {
    private final ao f1290a;
    private final aj f1291b;
    private final bn f1292c;

    public ak(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.buttonStyle);
    }

    public ak(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        this.f1290a = ao.m2497a();
        this.f1291b = new aj(this, this.f1290a);
        this.f1291b.m2479a(attributeSet, i);
        this.f1292c = bn.m2593a((TextView) this);
        this.f1292c.m2598a(attributeSet, i);
        this.f1292c.m2595a();
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1291b != null) {
            this.f1291b.m2482c();
        }
        if (this.f1292c != null) {
            this.f1292c.m2595a();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        return this.f1291b != null ? this.f1291b.m2474a() : null;
    }

    public Mode getSupportBackgroundTintMode() {
        return this.f1291b != null ? this.f1291b.m2480b() : null;
    }

    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        accessibilityEvent.setClassName(Button.class.getName());
    }

    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName(Button.class.getName());
    }

    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        if (this.f1291b != null) {
            this.f1291b.m2478a(drawable);
        }
    }

    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        if (this.f1291b != null) {
            this.f1291b.m2475a(i);
        }
    }

    public void setSupportAllCaps(boolean z) {
        if (this.f1292c != null) {
            this.f1292c.m2599a(z);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        if (this.f1291b != null) {
            this.f1291b.m2476a(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.f1291b != null) {
            this.f1291b.m2477a(mode);
        }
    }

    public void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        if (this.f1292c != null) {
            this.f1292c.m2596a(context, i);
        }
    }
}
