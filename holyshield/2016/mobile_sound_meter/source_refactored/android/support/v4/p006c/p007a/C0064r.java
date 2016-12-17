package android.support.v4.p006c.p007a;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.Callback;
import android.graphics.drawable.Drawable.ConstantState;

/* renamed from: android.support.v4.c.a.r */
class C0064r extends Drawable implements Callback, C0063q {
    static final Mode f344a;
    C0067s f345b;
    Drawable f346c;
    private int f347d;
    private Mode f348e;
    private boolean f349f;
    private boolean f350g;

    static {
        f344a = Mode.SRC_IN;
    }

    C0064r(Drawable drawable) {
        if (!(drawable == null || drawable.getConstantState() == null)) {
            this.f345b = m482b();
        }
        m481a(drawable);
    }

    C0064r(C0067s c0067s, Resources resources) {
        this.f345b = c0067s;
        m474a(resources);
    }

    private void m474a(Resources resources) {
        if (this.f345b != null && this.f345b.f352b != null) {
            m481a(m477a(this.f345b.f352b, resources));
        }
    }

    private boolean m475a(int[] iArr) {
        if (!m483c()) {
            return false;
        }
        ColorStateList colorStateList = this.f345b.f353c;
        Mode mode = this.f345b.f354d;
        if (colorStateList == null || mode == null) {
            this.f349f = false;
            clearColorFilter();
            return false;
        }
        int colorForState = colorStateList.getColorForState(iArr, colorStateList.getDefaultColor());
        if (this.f349f && colorForState == this.f347d && mode == this.f348e) {
            return false;
        }
        setColorFilter(colorForState, mode);
        this.f347d = colorForState;
        this.f348e = mode;
        this.f349f = true;
        return true;
    }

    public final Drawable m476a() {
        return this.f346c;
    }

    protected Drawable m477a(ConstantState constantState, Resources resources) {
        return constantState.newDrawable();
    }

    public void m478a(int i) {
        m479a(ColorStateList.valueOf(i));
    }

    public void m479a(ColorStateList colorStateList) {
        this.f345b.f353c = colorStateList;
        m475a(getState());
    }

    public void m480a(Mode mode) {
        this.f345b.f354d = mode;
        m475a(getState());
    }

    public final void m481a(Drawable drawable) {
        if (this.f346c != null) {
            this.f346c.setCallback(null);
        }
        this.f346c = drawable;
        if (drawable != null) {
            drawable.setCallback(this);
            drawable.setVisible(isVisible(), true);
            drawable.setState(getState());
            drawable.setLevel(getLevel());
            drawable.setBounds(getBounds());
            if (this.f345b != null) {
                this.f345b.f352b = drawable.getConstantState();
            }
        }
        invalidateSelf();
    }

    C0067s m482b() {
        return new C0083t(this.f345b, null);
    }

    protected boolean m483c() {
        return true;
    }

    public void draw(Canvas canvas) {
        this.f346c.draw(canvas);
    }

    public int getChangingConfigurations() {
        return ((this.f345b != null ? this.f345b.getChangingConfigurations() : 0) | super.getChangingConfigurations()) | this.f346c.getChangingConfigurations();
    }

    public ConstantState getConstantState() {
        if (this.f345b == null || !this.f345b.m488a()) {
            return null;
        }
        this.f345b.f351a = getChangingConfigurations();
        return this.f345b;
    }

    public Drawable getCurrent() {
        return this.f346c.getCurrent();
    }

    public int getIntrinsicHeight() {
        return this.f346c.getIntrinsicHeight();
    }

    public int getIntrinsicWidth() {
        return this.f346c.getIntrinsicWidth();
    }

    public int getMinimumHeight() {
        return this.f346c.getMinimumHeight();
    }

    public int getMinimumWidth() {
        return this.f346c.getMinimumWidth();
    }

    public int getOpacity() {
        return this.f346c.getOpacity();
    }

    public boolean getPadding(Rect rect) {
        return this.f346c.getPadding(rect);
    }

    public int[] getState() {
        return this.f346c.getState();
    }

    public Region getTransparentRegion() {
        return this.f346c.getTransparentRegion();
    }

    public void invalidateDrawable(Drawable drawable) {
        invalidateSelf();
    }

    public boolean isStateful() {
        ColorStateList colorStateList = m483c() ? this.f345b.f353c : null;
        return (colorStateList != null && colorStateList.isStateful()) || this.f346c.isStateful();
    }

    public Drawable mutate() {
        if (!this.f350g && super.mutate() == this) {
            this.f345b = m482b();
            if (this.f346c != null) {
                this.f346c.mutate();
            }
            if (this.f345b != null) {
                this.f345b.f352b = this.f346c != null ? this.f346c.getConstantState() : null;
            }
            this.f350g = true;
        }
        return this;
    }

    protected void onBoundsChange(Rect rect) {
        if (this.f346c != null) {
            this.f346c.setBounds(rect);
        }
    }

    protected boolean onLevelChange(int i) {
        return this.f346c.setLevel(i);
    }

    public void scheduleDrawable(Drawable drawable, Runnable runnable, long j) {
        scheduleSelf(runnable, j);
    }

    public void setAlpha(int i) {
        this.f346c.setAlpha(i);
    }

    public void setChangingConfigurations(int i) {
        this.f346c.setChangingConfigurations(i);
    }

    public void setColorFilter(ColorFilter colorFilter) {
        this.f346c.setColorFilter(colorFilter);
    }

    public void setDither(boolean z) {
        this.f346c.setDither(z);
    }

    public void setFilterBitmap(boolean z) {
        this.f346c.setFilterBitmap(z);
    }

    public boolean setState(int[] iArr) {
        return m475a(iArr) || this.f346c.setState(iArr);
    }

    public boolean setVisible(boolean z, boolean z2) {
        return super.setVisible(z, z2) || this.f346c.setVisible(z, z2);
    }

    public void unscheduleDrawable(Drawable drawable, Runnable runnable) {
        unscheduleSelf(runnable);
    }
}
