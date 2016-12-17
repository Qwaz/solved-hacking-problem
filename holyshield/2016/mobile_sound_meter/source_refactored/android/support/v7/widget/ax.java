package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff.Mode;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.bo;
import android.util.AttributeSet;
import android.widget.ImageView;

public class ax extends ImageView implements bo {
    private aj f1327a;
    private aw f1328b;

    public ax(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ax(Context context, AttributeSet attributeSet, int i) {
        super(de.m2707a(context), attributeSet, i);
        ao a = ao.m2497a();
        this.f1327a = new aj(this, a);
        this.f1327a.m2479a(attributeSet, i);
        this.f1328b = new aw(this, a);
        this.f1328b.m2530a(attributeSet, i);
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1327a != null) {
            this.f1327a.m2482c();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        return this.f1327a != null ? this.f1327a.m2474a() : null;
    }

    public Mode getSupportBackgroundTintMode() {
        return this.f1327a != null ? this.f1327a.m2480b() : null;
    }

    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        if (this.f1327a != null) {
            this.f1327a.m2478a(drawable);
        }
    }

    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        if (this.f1327a != null) {
            this.f1327a.m2475a(i);
        }
    }

    public void setImageResource(int i) {
        this.f1328b.m2529a(i);
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        if (this.f1327a != null) {
            this.f1327a.m2476a(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.f1327a != null) {
            this.f1327a.m2477a(mode);
        }
    }
}
